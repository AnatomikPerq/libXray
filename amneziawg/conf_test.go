package amneziawg

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xtls/xray-core/infra/conf"
)

func testKey(fill byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune(fill)), 32)))
}

func buildSettings(t *testing.T, settings string) (*DeviceConfig, error) {
	t.Helper()
	var config Config
	require.NoError(t, json.Unmarshal([]byte(settings), &config))
	message, err := config.Build()
	if err != nil {
		return nil, err
	}
	return message.(*DeviceConfig), nil
}

func TestBuildKeepsEveryAmneziaKeyInConfOrder(t *testing.T) {
	config, err := buildSettings(t, `{
		"secretKey": "`+testKey('a')+`",
		"address": ["10.8.0.2/32"],
		"remoteDNS": ["1.1.1.1"],
		"peers": [{
			"publicKey": "`+testKey('b')+`",
			"preSharedKey": "`+testKey('c')+`",
			"endpoint": "example.com:51820",
			"keepAlive": "25-35"
		}],
		"jc": 6, "jmin": 10, "jmax": 50,
		"s1": 12, "s2": 12, "s3": 12, "s4": 12,
		"h1": 1, "h2": "2", "h3": "100-200", "h4": "300-400",
		"i1": "<r 2><b 0x8580>",
		"headerProtectionKey": "`+testKey('d')+`",
		"rekeyAfterTime": "100-120", "rekeyTimeout": "3-7", "rejectAfterTime": "150-180",
		"keepaliveTimeout": "5-15", "maxHandshakeAttempts": "15-20",
		"randomTrailers": true, "disableCookies": true
	}`)
	require.NoError(t, err)

	var keys []string
	for _, option := range config.Options {
		keys = append(keys, option.Key+"="+option.Value)
	}
	require.Equal(t, []string{
		"jc=6", "jmin=10", "jmax=50",
		"s1=12", "s2=12", "s3=12", "s4=12",
		"h1=1", "h2=2", "h3=100-200", "h4=300-400",
		"i1=<r 2><b 0x8580>",
		"header_protection_key=" + strings.Repeat("64", 32),
		"rekey_after_time=100-120", "rekey_timeout=3-7", "reject_after_time=150-180",
		"keepalive_timeout=5-15", "max_handshake_attempts=15-20",
		"random_trailers=true", "disable_cookies=true",
	}, keys)
	require.Equal(t, strings.Repeat("61", 32), config.SecretKey)
	require.Equal(t, int32(DefaultMTU), config.Mtu)
	require.Equal(t, []string{"1.1.1.1"}, config.Dns)
	peer := config.Peers[0]
	require.Equal(t, strings.Repeat("62", 32), peer.PublicKey)
	require.Equal(t, strings.Repeat("63", 32), peer.PreSharedKey)
	require.Equal(t, "example.com:51820", peer.Endpoint)
	require.Equal(t, "25-35", peer.KeepAlive)
	require.Equal(t, []string{"0.0.0.0/0", "::/0"}, peer.AllowedIps)
}

func TestBuildWithoutAmneziaKeysIsPlainWireGuard(t *testing.T) {
	config, err := buildSettings(t, `{
		"secretKey": "`+testKey('a')+`",
		"address": ["10.8.0.2", "fd00::2/128"],
		"mtu": 1420,
		"peers": [{"publicKey": "`+testKey('b')+`", "endpoint": "[2001:db8::1]:51820", "keepAlive": 25, "allowedIPs": ["0.0.0.0/0"]}]
	}`)
	require.NoError(t, err)
	require.Empty(t, config.Options)
	require.Equal(t, int32(1420), config.Mtu)
	require.Equal(t, "[2001:db8::1]:51820", config.Peers[0].Endpoint)
	require.Equal(t, "25", config.Peers[0].KeepAlive)
	require.Equal(t, peersUAPI(config), strings.Join([]string{
		"public_key=" + strings.Repeat("62", 32),
		"endpoint=[2001:db8::1]:51820",
		"allowed_ip=0.0.0.0/0",
		"persistent_keepalive_interval=25",
		"",
	}, "\n"))
}

func TestBuildRefusesBrokenSettings(t *testing.T) {
	peer := `"peers": [{"publicKey": "` + testKey('b') + `", "endpoint": "1.2.3.4:51820"}]`
	base := `"secretKey": "` + testKey('a') + `", "address": ["10.8.0.2/32"]`
	for name, settings := range map[string]string{
		"no address":     `{"secretKey": "` + testKey('a') + `", ` + peer + `}`,
		"no peer":        `{` + base + `}`,
		"bad key":        `{"secretKey": "nope", "address": ["10.8.0.2/32"], ` + peer + `}`,
		"bad endpoint":   `{` + base + `, "peers": [{"publicKey": "` + testKey('b') + `", "endpoint": "1.2.3.4"}]}`,
		"jmin over jmax": `{` + base + `, ` + peer + `, "jmin": 60, "jmax": 50}`,
		"bad header key": `{` + base + `, ` + peer + `, "headerProtectionKey": "` + base64.StdEncoding.EncodeToString([]byte("short")) + `"}`,
		"padding":        `{` + base + `, ` + peer + `, "s4": 70000}`,
		"bad dns":        `{` + base + `, ` + peer + `, "remoteDNS": ["dns.google"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := buildSettings(t, settings)
			require.Error(t, err)
		})
	}

	var config Config
	require.Error(t, json.Unmarshal([]byte(`{"h1": "20-10"}`), &config))
	require.Error(t, json.Unmarshal([]byte(`{"h1": true}`), &config))
}

func TestXrayLoadsTheAmneziawgProtocol(t *testing.T) {
	var outbound conf.OutboundDetourConfig
	require.NoError(t, json.Unmarshal([]byte(`{
		"tag": "awg",
		"protocol": "amneziawg",
		"settings": {
			"secretKey": "`+testKey('a')+`",
			"address": ["10.8.0.2/32"],
			"peers": [{"publicKey": "`+testKey('b')+`", "endpoint": "1.2.3.4:51820"}],
			"jc": 4
		}
	}`), &outbound))
	handler, err := outbound.Build()
	require.NoError(t, err)
	instance, err := handler.ProxySettings.GetInstance()
	require.NoError(t, err)
	require.Equal(t, "jc", instance.(*DeviceConfig).Options[0].Key)
}
