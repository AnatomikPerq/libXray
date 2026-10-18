// Package amneziawg is the "amneziawg" outbound of Xray: Xray's WireGuard
// client on amneziawg-go v3, so a node of AmneziaWG up to 3.1 (and of plain
// WireGuard, which is AmneziaWG without its keys) is an ordinary outbound
// of the Core with UDP, routing, balancers, stats and the live switch.
//
// Importing the package registers the protocol: the config type with Xray's
// object registry and the "amneziawg" settings with its JSON loader.
package amneziawg

import (
	"context"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/infra/conf"
)

// Protocol is the "protocol" of the outbound in Xray JSON.
const Protocol = "amneziawg"

func init() {
	common.Must(common.RegisterConfig((*DeviceConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*DeviceConfig))
	}))
	common.Must(registerOutbound(Protocol, func() interface{} { return new(Config) }))
}

// outboundConfigLoader is the loader conf.OutboundDetourConfig.Build reads
// "settings" with. Xray offers no way to add a protocol to it from outside.
//
//go:linkname outboundConfigLoader github.com/xtls/xray-core/infra/conf.outboundConfigLoader
var outboundConfigLoader *conf.JSONConfigLoader

// registerOutbound adds a protocol to Xray's outbound loader. The loader
// keeps its protocols in the unexported field "cache"; the checks make a
// changed Xray fail at start (and in the tests) instead of misbehaving.
func registerOutbound(protocol string, creator conf.ConfigCreator) error {
	if outboundConfigLoader == nil {
		return fmt.Errorf("Xray's outbound config loader is missing")
	}
	field := reflect.ValueOf(outboundConfigLoader).Elem().FieldByName("cache")
	if !field.IsValid() || field.Type() != reflect.TypeOf(conf.ConfigCreatorCache(nil)) {
		return fmt.Errorf("Xray's outbound config loader has changed")
	}
	cache := *(*conf.ConfigCreatorCache)(unsafe.Pointer(field.UnsafeAddr()))
	if cache == nil {
		return fmt.Errorf("Xray's outbound config loader is empty")
	}
	return cache.RegisterCreator(protocol, creator)
}
