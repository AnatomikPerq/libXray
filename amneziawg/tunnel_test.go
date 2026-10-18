package amneziawg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	stdnet "net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/stretchr/testify/require"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/proxy"
)

// Everything here stays on 127.0.0.1: the server is an AmneziaWG device in
// this process, the client a Core with loopback inbounds.

type keyPair struct{ private, public []byte }

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	private := make([]byte, 32)
	_, err := rand.Read(private)
	require.NoError(t, err)
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	require.NoError(t, err)
	return keyPair{private, public}
}

func (k keyPair) privateBase64() string { return base64.StdEncoding.EncodeToString(k.private) }
func (k keyPair) publicBase64() string  { return base64.StdEncoding.EncodeToString(k.public) }

// echo answers every TCP stream and UDP datagram that reaches the server's
// side of the tunnel with what it got.
type echo struct{}

func (echo) HandleConnection(conn stdnet.Conn, dest net.Destination) {
	defer conn.Close()
	if dest.Network == net.Network_TCP {
		_, _ = io.Copy(conn, conn)
		return
	}
	packet := make([]byte, 2048)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(packet)
		if err != nil {
			return
		}
		if _, err := conn.Write(packet[:n]); err != nil {
			return
		}
	}
}

// startServer runs an AmneziaWG device with the given UAPI keys on a loopback
// port and returns its endpoint.
func startServer(t *testing.T, server, client keyPair, options string) string {
	t.Helper()
	udp, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	serverBind := &bind{
		ctx:        context.Background(),
		listenFunc: func(context.Context) (net.PacketConn, error) { return udp, nil },
	}
	tunDevice, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, DefaultMTU, echo{})
	require.NoError(t, err)
	dev := device.NewDevice(tunDevice, serverBind, device.NewLogger(device.LogLevelSilent, ""))
	serverBind.downFunc = dev.Down
	t.Cleanup(dev.Close)
	require.NoError(t, dev.IpcSet(
		"private_key="+hex.EncodeToString(server.private)+"\n"+
			options+
			"public_key="+hex.EncodeToString(client.public)+"\n"+
			"allowed_ip=10.77.0.2/32\n"))
	tunDevice.(*netTun).WakeReader()
	require.NoError(t, dev.Up())
	return udp.LocalAddr().String()
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().(*stdnet.TCPAddr).Port
}

// startClient runs a Core with a SOCKS inbound and a UDP tunnel inbound to
// 10.9.9.9:7, both sent to the outbound.
func startClient(t *testing.T, outbound string) (socks, udp string) {
	t.Helper()
	socksPort, udpPort := freePort(t), freePort(t)
	config := fmt.Sprintf(`{
		"log": {"loglevel": "none"},
		"inbounds": [
			{"protocol": "socks", "listen": "127.0.0.1", "port": %d, "settings": {"udp": true}},
			{"protocol": "tunnel", "listen": "127.0.0.1", "port": %d, "settings": {"address": "10.9.9.9", "port": 7, "network": "udp"}}
		],
		"outbounds": [%s]
	}`, socksPort, udpPort, outbound)
	loaded, err := core.LoadConfig("json", strings.NewReader(config))
	require.NoError(t, err)
	instance, err := core.New(loaded)
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { _ = instance.Close() })
	return fmt.Sprintf("127.0.0.1:%d", socksPort), fmt.Sprintf("127.0.0.1:%d", udpPort)
}

func amneziaOutbound(server, client keyPair, endpoint, extra string) string {
	return `{"protocol": "amneziawg", "settings": {
		"secretKey": "` + client.privateBase64() + `",
		"address": ["10.77.0.2/32"],
		"peers": [{"publicKey": "` + server.publicBase64() + `", "endpoint": "` + endpoint + `", "keepAlive": "25-35"}]` +
		extra + `}}`
}

func roundTripTCP(socks, target, message string) (string, error) {
	dialer, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		return "", err
	}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(message)); err != nil {
		return "", err
	}
	reply := make([]byte, len(message))
	_, err = io.ReadFull(conn, reply)
	return string(reply), err
}

func roundTripUDP(target, message string) (string, error) {
	conn, err := stdnet.Dial("udp4", target)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(message)); err != nil {
		return "", err
	}
	reply := make([]byte, 2048)
	n, err := conn.Read(reply)
	return string(reply[:n]), err
}

// The keys of a real AmneziaWG 3.1 config, header protection included.
const amneziaUAPI = "jc=6\njmin=10\njmax=50\ns1=12\ns2=12\ns3=12\ns4=12\n" +
	"h1=1000-2000\nh2=3000-4000\nh3=5000-6000\nh4=7000-8000\n" +
	"rekey_after_time=100-120\nrekey_timeout=3-7\nreject_after_time=150-180\n" +
	"keepalive_timeout=5-15\nmax_handshake_attempts=15-20\n" +
	"random_trailers=true\ndisable_cookies=true\n"

const amneziaJSON = `, "jc": 6, "jmin": 10, "jmax": 50, "s1": 12, "s2": 12, "s3": 12, "s4": 12,
	"h1": "1000-2000", "h2": "3000-4000", "h3": "5000-6000", "h4": "7000-8000",
	"i1": "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001>",
	"rekeyAfterTime": "100-120", "rekeyTimeout": "3-7", "rejectAfterTime": "150-180",
	"keepaliveTimeout": "5-15", "maxHandshakeAttempts": "15-20",
	"randomTrailers": true, "disableCookies": true`

func TestAmneziaWGCarriesTCPAndUDP(t *testing.T) {
	server, client, protection := newKeyPair(t), newKeyPair(t), newKeyPair(t)
	endpoint := startServer(t, server, client, amneziaUAPI+"header_protection_key="+hex.EncodeToString(protection.private)+"\n")
	socks, udp := startClient(t, amneziaOutbound(server, client, endpoint,
		amneziaJSON+`, "headerProtectionKey": "`+protection.privateBase64()+`"`))

	// A datagram first: one lost before the handshake is not sent again (S4
	// padding, see netTun.WakeReader).
	start := time.Now()
	reply, err := roundTripUDP(udp, "datagram over amneziawg")
	require.NoError(t, err)
	require.Equal(t, "datagram over amneziawg", reply)
	require.Less(t, time.Since(start), 2*time.Second)

	reply, err = roundTripTCP(socks, "10.9.9.9:80", "hello over amneziawg")
	require.NoError(t, err)
	require.Equal(t, "hello over amneziawg", reply)
}

func TestAmneziaWGWithOtherHeadersGetsNoHandshake(t *testing.T) {
	server, client := newKeyPair(t), newKeyPair(t)
	endpoint := startServer(t, server, client, amneziaUAPI)
	socks, _ := startClient(t, amneziaOutbound(server, client, endpoint,
		strings.Replace(amneziaJSON, `"h1": "1000-2000"`, `"h1": "9000-9100"`, 1)))

	_, err := roundTripTCP(socks, "10.9.9.9:80", "lost")
	require.Error(t, err)
}

func TestBadAmneziaKeysFailWhenTheCoreIsMade(t *testing.T) {
	server, client := newKeyPair(t), newKeyPair(t)
	config := `{"log": {"loglevel": "none"}, "outbounds": [` +
		amneziaOutbound(server, client, "127.0.0.1:9", `, "i1": "<nope 1>"`) + `]}`
	loaded, err := core.LoadConfig("json", strings.NewReader(config))
	require.NoError(t, err)
	_, err = core.New(loaded)
	require.ErrorContains(t, err, "AmneziaWG")
}

// Without its keys the outbound speaks plain WireGuard: Xray's own WireGuard
// inbound (upstream wireguard-go) serves it here and redirects the stream to a
// loopback echo server (a loopback target would never enter the tunnel).
func TestPlainWireGuardServerAcceptsTheOutbound(t *testing.T) {
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()

	server, client := newKeyPair(t), newKeyPair(t)
	wgPort := freePort(t)
	serverConfig := fmt.Sprintf(`{
		"log": {"loglevel": "none"},
		"inbounds": [{"protocol": "wireguard", "listen": "127.0.0.1", "port": %d, "settings": {
			"secretKey": "%s", "mtu": 1280,
			"peers": [{"publicKey": "%s", "allowedIPs": ["10.77.0.2/32"]}]
		}}],
		"outbounds": [{"protocol": "freedom", "settings": {"redirect": "%s", "finalRules": [{"action": "allow"}]}}]
	}`, wgPort, server.privateBase64(), client.publicBase64(), listener.Addr())
	loaded, err := core.LoadConfig("json", strings.NewReader(serverConfig))
	require.NoError(t, err)
	instance, err := core.New(loaded)
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	defer instance.Close()

	socks, _ := startClient(t, amneziaOutbound(server, client, fmt.Sprintf("127.0.0.1:%d", wgPort), ""))
	reply, err := roundTripTCP(socks, "10.9.9.9:80", "plain wireguard")
	require.NoError(t, err)
	require.Equal(t, "plain wireguard", reply)
}
