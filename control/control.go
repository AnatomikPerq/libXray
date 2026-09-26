// Package control changes a running desktop Core without restarting it.
//
// On Windows the TUN Core runs elevated, so every restart costs the user a UAC
// prompt. Switching nodes only swaps outbounds (and a few tagged routing
// rules), which Xray's HandlerService and RoutingService can do on the live
// instance.
//
// Xray's gRPC API has no authentication of its own, and anyone who reaches it
// can add inbounds or reroute traffic of an elevated process. The Core
// therefore never opens a raw API listener. The App generates a loopback SOCKS5
// inbound with a random per-session password and routes it to the `api`
// outbound; this client dials the API through that inbound, so knowing the port
// alone is not enough.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	routerService "github.com/xtls/xray-core/app/router/command"
	cserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Operation kinds, applied in request order.
const (
	OpRemoveOutbound = "removeOutbound"
	OpAddOutbound    = "addOutbound"
	OpRemoveRule     = "removeRule"
	OpAddRules       = "addRules"
)

const (
	defaultTimeout = 5 * time.Second
	maxTimeout     = 30 * time.Second
	// The SOCKS5 CONNECT target is irrelevant: the routing rule matches the
	// inbound tag before any destination-based rule is considered.
	apiDestination = "127.0.0.1:1"
)

// Request describes a batch of changes for one running Core.
type Request struct {
	// Server is the loopback SOCKS5 inbound that is routed to the API.
	Server         string      `json:"server"`
	Username       string      `json:"username"`
	Password       string      `json:"password"`
	TimeoutSeconds int         `json:"timeoutSeconds,omitempty"`
	Operations     []Operation `json:"operations"`
}

// Operation is one API call.
type Operation struct {
	Op string `json:"op"`
	// Tag names the outbound to remove, or the rule tag to remove.
	Tag string `json:"tag,omitempty"`
	// Outbound is one Xray outbound object for OpAddOutbound.
	Outbound json.RawMessage `json:"outbound,omitempty"`
	// Routing is an Xray `routing` object for OpAddRules; only its rules and
	// balancers are applied, never its domainStrategy.
	Routing json.RawMessage `json:"routing,omitempty"`
	// Append keeps the current rules and balancers and adds these after them.
	// Without it Xray REPLACES every rule and balancer with the given ones in
	// one step, so the routing must include the rule that keeps the control
	// inbound on the api outbound.
	Append bool `json:"append,omitempty"`
}

// Error reports which operation failed, so the caller knows how far the live
// Core got before deciding how to recover.
type Error struct {
	Index int
	Op    string
	Err   error
}

func (e *Error) Error() string {
	return fmt.Sprintf("control operation %d (%s): %v", e.Index, e.Op, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Apply runs every operation in order and stops at the first failure.
func Apply(request Request) error {
	if err := validate(request); err != nil {
		return err
	}
	timeout := defaultTimeout
	if request.TimeoutSeconds > 0 {
		timeout = time.Duration(request.TimeoutSeconds) * time.Second
		if timeout > maxTimeout {
			timeout = maxTimeout
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dial(request)
	if err != nil {
		return err
	}
	defer conn.Close()

	handlers := handlerService.NewHandlerServiceClient(conn)
	router := routerService.NewRoutingServiceClient(conn)
	for index, operation := range request.Operations {
		if err := apply(ctx, handlers, router, operation); err != nil {
			return &Error{Index: index, Op: operation.Op, Err: err}
		}
	}
	return nil
}

func validate(request Request) error {
	host, port, err := net.SplitHostPort(request.Server)
	if err != nil {
		return fmt.Errorf("control server: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("control server must be a loopback IP address")
	}
	if port == "" || port == "0" {
		return errors.New("control server port is required")
	}
	if request.Username == "" || request.Password == "" {
		return errors.New("control credentials are required")
	}
	if len(request.Operations) == 0 {
		return errors.New("no control operations")
	}
	for index, operation := range request.Operations {
		switch operation.Op {
		case OpRemoveOutbound, OpRemoveRule:
			if strings.TrimSpace(operation.Tag) == "" {
				return fmt.Errorf("control operation %d (%s): tag is required", index, operation.Op)
			}
		case OpAddOutbound:
			if len(operation.Outbound) == 0 {
				return fmt.Errorf("control operation %d (%s): outbound is required", index, operation.Op)
			}
		case OpAddRules:
			if len(operation.Routing) == 0 {
				return fmt.Errorf("control operation %d (%s): routing is required", index, operation.Op)
			}
		default:
			return fmt.Errorf("control operation %d: unknown op %q", index, operation.Op)
		}
	}
	return nil
}

func dial(request Request) (*grpc.ClientConn, error) {
	socks, err := proxy.SOCKS5("tcp", request.Server, &proxy.Auth{
		User:     request.Username,
		Password: request.Password,
	}, &net.Dialer{Timeout: defaultTimeout})
	if err != nil {
		return nil, err
	}
	contextDialer, ok := socks.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("socks dialer does not support contexts")
	}
	return grpc.NewClient(
		"passthrough:///xray-api",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return contextDialer.DialContext(ctx, "tcp", apiDestination)
		}),
	)
}

func apply(
	ctx context.Context,
	handlers handlerService.HandlerServiceClient,
	router routerService.RoutingServiceClient,
	operation Operation,
) error {
	switch operation.Op {
	case OpRemoveOutbound:
		_, err := handlers.RemoveOutbound(ctx, &handlerService.RemoveOutboundRequest{Tag: operation.Tag})
		return err
	case OpAddOutbound:
		var detour conf.OutboundDetourConfig
		if err := json.Unmarshal(operation.Outbound, &detour); err != nil {
			return err
		}
		outbound, err := detour.Build()
		if err != nil {
			return err
		}
		_, err = handlers.AddOutbound(ctx, &handlerService.AddOutboundRequest{Outbound: outbound})
		return err
	case OpRemoveRule:
		_, err := router.RemoveRule(ctx, &routerService.RemoveRuleRequest{RuleTag: operation.Tag})
		return err
	case OpAddRules:
		var routing conf.RouterConfig
		if err := json.Unmarshal(operation.Routing, &routing); err != nil {
			return err
		}
		config, err := routing.Build()
		if err != nil {
			return err
		}
		_, err = router.AddRule(ctx, &routerService.AddRuleRequest{
			Config:       cserial.ToTypedMessage(config),
			ShouldAppend: operation.Append,
		})
		return err
	}
	return fmt.Errorf("unknown op %q", operation.Op)
}
