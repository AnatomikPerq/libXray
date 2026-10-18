package amneziawg

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

// DefaultMTU leaves room on a 1500-byte path for the WireGuard header, the
// paddings and junk Amnezia adds, and the outer IPv6 header.
const DefaultMTU = 1280

// Config is the "settings" of an "amneziawg" outbound. The common part is
// Xray's "wireguard" outbound; the rest are the AmneziaWG keys of a .conf
// file in camelCase. Keys of AmneziaWG 1.5 (J1-J3, Itime) are gone from the
// engine and are not accepted.
type Config struct {
	SecretKey string            `json:"secretKey"`
	Address   []string          `json:"address"`
	Peers     []*PeerConfigJSON `json:"peers"`
	MTU       int32             `json:"mtu"`
	DNS       []string          `json:"remoteDNS"`

	Jc   *uint32 `json:"jc"`
	Jmin *uint32 `json:"jmin"`
	Jmax *uint32 `json:"jmax"`
	S1   *uint32 `json:"s1"`
	S2   *uint32 `json:"s2"`
	S3   *uint32 `json:"s3"`
	S4   *uint32 `json:"s4"`
	H1   *Range  `json:"h1"`
	H2   *Range  `json:"h2"`
	H3   *Range  `json:"h3"`
	H4   *Range  `json:"h4"`
	I1   string  `json:"i1"`
	I2   string  `json:"i2"`
	I3   string  `json:"i3"`
	I4   string  `json:"i4"`
	I5   string  `json:"i5"`

	HeaderProtectionKey    string `json:"headerProtectionKey"`
	ContentPaddingAddition *Range `json:"contentPaddingAddition"`
	RekeyAfterTime         *Range `json:"rekeyAfterTime"`
	RekeyTimeout           *Range `json:"rekeyTimeout"`
	RejectAfterTime        *Range `json:"rejectAfterTime"`
	KeepaliveTimeout       *Range `json:"keepaliveTimeout"`
	MaxHandshakeAttempts   *Range `json:"maxHandshakeAttempts"`
	RandomTrailers         *bool  `json:"randomTrailers"`
	DisableCookies         *bool  `json:"disableCookies"`
}

type PeerConfigJSON struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    *Range   `json:"keepAlive"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`
}

// Range is a number or a range "lo-hi" the engine picks from each time, as
// AmneziaWG 2.0 writes headers, timings and keepalive. JSON takes a number or
// a string.
type Range struct {
	Lo, Hi uint32
}

func (r *Range) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		var number uint32
		if err := json.Unmarshal(data, &number); err != nil {
			return fmt.Errorf("want a number or a range like \"10-20\", got %s", data)
		}
		*r = Range{number, number}
		return nil
	}
	parsed, err := ParseRange(text)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

func ParseRange(text string) (Range, error) {
	lo, hi, isRange := strings.Cut(strings.TrimSpace(text), "-")
	low, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 32)
	if err != nil {
		return Range{}, fmt.Errorf("invalid number or range %q", text)
	}
	high := low
	if isRange {
		high, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 32)
		if err != nil || high < low {
			return Range{}, fmt.Errorf("invalid range %q", text)
		}
	}
	return Range{uint32(low), uint32(high)}, nil
}

func (r Range) String() string {
	if r.Lo == r.Hi {
		return strconv.FormatUint(uint64(r.Lo), 10)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// Build implements conf.Buildable.
func (c *Config) Build() (proto.Message, error) {
	config := new(DeviceConfig)
	var err error
	if config.SecretKey, err = parseKey(c.SecretKey); err != nil {
		return nil, fmt.Errorf("invalid AmneziaWG secret key: %w", err)
	}
	if len(c.Address) == 0 {
		return nil, fmt.Errorf("AmneziaWG needs the address of this side in the tunnel")
	}
	for _, address := range c.Address {
		if _, err := parseAddress(address); err != nil {
			return nil, err
		}
	}
	config.Address = c.Address
	for _, server := range c.DNS {
		if _, err := netip.ParseAddr(server); err != nil {
			return nil, fmt.Errorf("invalid AmneziaWG remoteDNS %q", server)
		}
	}
	config.Dns = c.DNS
	if len(c.Peers) == 0 {
		return nil, fmt.Errorf("AmneziaWG needs a peer")
	}
	for _, peer := range c.Peers {
		built, err := peer.build()
		if err != nil {
			return nil, err
		}
		config.Peers = append(config.Peers, built)
	}
	config.Mtu = c.MTU
	if config.Mtu == 0 {
		config.Mtu = DefaultMTU
	}
	if config.Mtu < 576 || config.Mtu > 65535 {
		return nil, fmt.Errorf("invalid AmneziaWG mtu %d", config.Mtu)
	}
	if config.Options, err = c.options(); err != nil {
		return nil, err
	}
	return config, nil
}

// options are the device keys in UAPI form, in the order of a .conf file.
// The engine checks them again when the device is made (overlapping headers,
// paddings too short for header protection, the I1-I5 tags).
func (c *Config) options() ([]*Option, error) {
	var options []*Option
	add := func(key, value string) { options = append(options, &Option{Key: key, Value: value}) }
	number := func(key string, value *uint32) {
		if value != nil {
			add(key, strconv.FormatUint(uint64(*value), 10))
		}
	}
	span := func(key string, value *Range) {
		if value != nil {
			add(key, value.String())
		}
	}
	flag := func(key string, value *bool) {
		if value != nil {
			add(key, strconv.FormatBool(*value))
		}
	}
	number("jc", c.Jc)
	number("jmin", c.Jmin)
	number("jmax", c.Jmax)
	if c.Jmin != nil && c.Jmax != nil && *c.Jmin > *c.Jmax {
		return nil, fmt.Errorf("AmneziaWG jmin %d is above jmax %d", *c.Jmin, *c.Jmax)
	}
	for i, padding := range []*uint32{c.S1, c.S2, c.S3, c.S4} {
		if padding != nil && *padding > 65535 {
			return nil, fmt.Errorf("AmneziaWG s%d %d is above 65535", i+1, *padding)
		}
		number(fmt.Sprintf("s%d", i+1), padding)
	}
	for i, header := range []*Range{c.H1, c.H2, c.H3, c.H4} {
		span(fmt.Sprintf("h%d", i+1), header)
	}
	for i, packet := range []string{c.I1, c.I2, c.I3, c.I4, c.I5} {
		if packet = strings.TrimSpace(packet); packet != "" {
			if strings.ContainsAny(packet, "\r\n") {
				return nil, fmt.Errorf("AmneziaWG i%d spans lines", i+1)
			}
			add(fmt.Sprintf("i%d", i+1), packet)
		}
	}
	if c.HeaderProtectionKey != "" {
		key, err := parseKey(c.HeaderProtectionKey)
		if err != nil {
			return nil, fmt.Errorf("invalid AmneziaWG headerProtectionKey: %w", err)
		}
		add("header_protection_key", key)
	}
	span("content_padding_addition", c.ContentPaddingAddition)
	span("rekey_after_time", c.RekeyAfterTime)
	span("rekey_timeout", c.RekeyTimeout)
	span("reject_after_time", c.RejectAfterTime)
	span("keepalive_timeout", c.KeepaliveTimeout)
	span("max_handshake_attempts", c.MaxHandshakeAttempts)
	flag("random_trailers", c.RandomTrailers)
	flag("disable_cookies", c.DisableCookies)
	return options, nil
}

func (c *PeerConfigJSON) build() (*PeerConfig, error) {
	config := new(PeerConfig)
	var err error
	if config.PublicKey, err = parseKey(c.PublicKey); err != nil {
		return nil, fmt.Errorf("invalid AmneziaWG peer public key: %w", err)
	}
	if c.PreSharedKey != "" {
		if config.PreSharedKey, err = parseKey(c.PreSharedKey); err != nil {
			return nil, fmt.Errorf("invalid AmneziaWG peer preshared key: %w", err)
		}
	}
	host, port, err := splitEndpoint(c.Endpoint)
	if err != nil {
		return nil, err
	}
	config.Endpoint = joinEndpoint(host, port)
	if c.KeepAlive != nil && (c.KeepAlive.Lo != 0 || c.KeepAlive.Hi != 0) {
		if c.KeepAlive.Hi > 65535 {
			return nil, fmt.Errorf("invalid AmneziaWG peer keepAlive %s", c.KeepAlive)
		}
		config.KeepAlive = c.KeepAlive.String()
	}
	config.AllowedIps = c.AllowedIPs
	if len(config.AllowedIps) == 0 {
		config.AllowedIps = []string{"0.0.0.0/0", "::/0"}
	}
	for _, prefix := range config.AllowedIps {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			return nil, fmt.Errorf("invalid AmneziaWG peer allowedIPs %q", prefix)
		}
	}
	return config, nil
}

// parseKey takes a 32-byte key in base64 (as .conf files write it) or hex
// and returns hex, as the UAPI wants it.
func parseKey(text string) (string, error) {
	key, err := conf.ParseWireGuardKey(strings.TrimSpace(text))
	if err != nil {
		return "", err
	}
	if len(key) != 64 {
		return "", fmt.Errorf("a key has 32 bytes")
	}
	return key, nil
}

// parseAddress takes an address with or without a prefix, as .conf files
// write "10.8.0.2/32" and Xray configs often "10.8.0.2".
func parseAddress(address string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(address); err == nil {
		return addr, nil
	}
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid AmneziaWG address %q", address)
	}
	return prefix.Addr(), nil
}

func splitEndpoint(endpoint string) (string, uint16, error) {
	endpoint = strings.TrimSpace(endpoint)
	index := strings.LastIndex(endpoint, ":")
	if index <= 0 {
		return "", 0, fmt.Errorf("invalid AmneziaWG peer endpoint %q", endpoint)
	}
	host := strings.TrimSuffix(strings.TrimPrefix(endpoint[:index], "["), "]")
	port, err := strconv.ParseUint(endpoint[index+1:], 10, 16)
	if err != nil || port == 0 || host == "" {
		return "", 0, fmt.Errorf("invalid AmneziaWG peer endpoint %q", endpoint)
	}
	return host, uint16(port), nil
}

func joinEndpoint(host string, port uint16) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(int(port))
	}
	return host + ":" + strconv.Itoa(int(port))
}
