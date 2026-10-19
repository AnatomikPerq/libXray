package control

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"google.golang.org/protobuf/proto"
)

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func startCore(t *testing.T, port int, password string) *core.Instance {
	t.Helper()
	raw := fmt.Sprintf(`{
  "log": {"loglevel": "none"},
  "api": {"tag": "api", "services": ["HandlerService", "RoutingService"]},
  "inbounds": [{
    "tag": "app-control",
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "socks",
    "settings": {"auth": "password", "accounts": [{"user": "app", "pass": %q}], "udp": false}
  }],
  "outbounds": [
    {"tag": "proxy-old", "protocol": "freedom"},
    {"tag": "direct", "protocol": "freedom"}
  ],
  "routing": {"rules": [
    {"inboundTag": ["app-control"], "outboundTag": "api"},
    {"ruleTag": "bypass-old", "ip": ["203.0.113.1"], "outboundTag": "direct"}
  ]}
}`, port, password)
	config, err := serial.DecodeJSONConfig(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	return instance
}

func handler(instance *core.Instance, tag string) outbound.Handler {
	manager := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	return manager.GetHandler(tag)
}

func TestApplySwapsOutboundAndRulesOnLiveCore(t *testing.T) {
	port := freePort(t)
	instance := startCore(t, port, "secret")

	err := Apply(Request{
		Server:   fmt.Sprintf("127.0.0.1:%d", port),
		Username: "app",
		Password: "secret",
		Operations: []Operation{
			{Op: OpRemoveRule, Tag: "bypass-old"},
			{Op: OpRemoveOutbound, Tag: "proxy-old"},
			{Op: OpAddOutbound, Outbound: json.RawMessage(`{"tag":"proxy-new","protocol":"freedom"}`)},
			// A full replacement: it has to keep the control rule itself.
			{Op: OpAddRules, Routing: json.RawMessage(`{"rules":[
				{"inboundTag":["app-control"],"outboundTag":"api"},
				{"ruleTag":"bypass-new","ip":["203.0.113.2"],"outboundTag":"direct"}]}`)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The API is still reachable after the rules were replaced.
	if err := Apply(Request{
		Server:     fmt.Sprintf("127.0.0.1:%d", port),
		Username:   "app",
		Password:   "secret",
		Operations: []Operation{{Op: OpRemoveRule, Tag: "bypass-new"}},
	}); err != nil {
		t.Fatalf("API lost after replacing rules: %v", err)
	}
	if handler(instance, "proxy-old") != nil {
		t.Fatal("old outbound is still registered")
	}
	if handler(instance, "proxy-new") == nil {
		t.Fatal("new outbound was not added")
	}
	// The removed default handler must be replaced by the first added one, or
	// traffic that matches no rule would have nowhere to go.
	manager := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if got := manager.GetDefaultHandler(); got == nil || got.Tag() != "proxy-new" {
		t.Fatalf("default handler = %v, want proxy-new", got)
	}
}

func TestApplyRejectsWrongPassword(t *testing.T) {
	port := freePort(t)
	instance := startCore(t, port, "secret")

	err := Apply(Request{
		Server:     fmt.Sprintf("127.0.0.1:%d", port),
		Username:   "app",
		Password:   "guess",
		Operations: []Operation{{Op: OpRemoveOutbound, Tag: "proxy-old"}},
	})
	if err == nil {
		t.Fatal("API accepted a wrong password")
	}
	if handler(instance, "proxy-old") == nil {
		t.Fatal("outbound was removed without valid credentials")
	}
}

func TestApplyReportsFailingOperation(t *testing.T) {
	port := freePort(t)
	startCore(t, port, "secret")

	err := Apply(Request{
		Server:   fmt.Sprintf("127.0.0.1:%d", port),
		Username: "app",
		Password: "secret",
		Operations: []Operation{
			{Op: OpRemoveOutbound, Tag: "proxy-old"},
			// Duplicate tag: Xray refuses it.
			{Op: OpAddOutbound, Outbound: json.RawMessage(`{"tag":"direct","protocol":"freedom"}`)},
		},
	})
	var controlErr *Error
	if err == nil || !asControlError(err, &controlErr) || controlErr.Index != 1 {
		t.Fatalf("err = %v, want failure at operation 1", err)
	}
}

func asControlError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

func TestValidateRejectsUnsafeRequests(t *testing.T) {
	base := Request{
		Server:     "127.0.0.1:1080",
		Username:   "app",
		Password:   "secret",
		Operations: []Operation{{Op: OpRemoveOutbound, Tag: "proxy"}},
	}
	cases := map[string]func(r *Request){
		"remote host":     func(r *Request) { r.Server = "192.168.1.10:1080" },
		"hostname":        func(r *Request) { r.Server = "localhost:1080" },
		"no password":     func(r *Request) { r.Password = "" },
		"no operations":   func(r *Request) { r.Operations = nil },
		"unknown op":      func(r *Request) { r.Operations = []Operation{{Op: "addInbound"}} },
		"empty tag":       func(r *Request) { r.Operations = []Operation{{Op: OpRemoveRule}} },
		"empty outbound":  func(r *Request) { r.Operations = []Operation{{Op: OpAddOutbound}} },
		"empty routing":   func(r *Request) { r.Operations = []Operation{{Op: OpAddRules}} },
		"no port":         func(r *Request) { r.Server = "127.0.0.1:0" },
		"malformed input": func(r *Request) { r.Server = "127.0.0.1" },
	}
	for name, mutate := range cases {
		request := base
		mutate(&request)
		if err := validate(request); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := validate(base); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

// geoAssetDir writes a geosite.dat with one TEST list, the way the App's dat
// directory holds the real one.
func geoAssetDir(t *testing.T) string {
	t.Helper()
	list := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{{
		Code:   "TEST",
		Domain: []*geodata.Domain{{Type: geodata.Domain_Full, Value: "example.com"}},
	}}}
	bytes, err := proto.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestApplyBuildsGeoRulesFromAssetDir(t *testing.T) {
	// The App process has no asset location of its own.
	t.Setenv(platform.AssetLocation, "")
	port := freePort(t)
	instance := startCore(t, port, "secret")
	request := Request{
		Server:   fmt.Sprintf("127.0.0.1:%d", port),
		Username: "app",
		Password: "secret",
		Operations: []Operation{
			{Op: OpRemoveOutbound, Tag: "proxy-old"},
			{Op: OpAddOutbound, Outbound: json.RawMessage(`{"tag":"proxy-new","protocol":"freedom"}`)},
			{Op: OpAddRules, Routing: json.RawMessage(`{"rules":[
				{"inboundTag":["app-control"],"outboundTag":"api"},
				{"domain":["geosite:TEST"],"outboundTag":"direct"}]}`)},
		},
	}

	err := Apply(request)
	var controlErr *Error
	if err == nil || !asControlError(err, &controlErr) || controlErr.Index != 2 || controlErr.Built {
		t.Fatalf("err = %v, want operation 2 failing to build without the asset dir", err)
	}
	// Nothing was sent: a request that cannot be built leaves the Core as it was.
	if handler(instance, "proxy-old") == nil || handler(instance, "proxy-new") != nil {
		t.Fatal("the Core changed although the request could not be built")
	}

	request.AssetDir = geoAssetDir(t)
	if err := Apply(request); err != nil {
		t.Fatalf("geosite rule with asset dir: %v", err)
	}
	if handler(instance, "proxy-new") == nil {
		t.Fatal("new outbound was not added")
	}
}

func TestValidateRejectsRelativeAssetDir(t *testing.T) {
	err := validate(Request{
		Server:     "127.0.0.1:1",
		Username:   "app",
		Password:   "secret",
		Operations: []Operation{{Op: OpRemoveRule, Tag: "x"}},
		AssetDir:   "dat",
	})
	if err == nil {
		t.Fatal("relative asset dir accepted")
	}
}
