package control

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
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
			{Op: OpAddRules, Routing: json.RawMessage(`{"rules":[{"ruleTag":"bypass-new","ip":["203.0.113.2"],"outboundTag":"direct"}]}`)},
		},
	})
	if err != nil {
		t.Fatal(err)
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
