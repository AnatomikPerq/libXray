# amneziawg: the AmneziaWG outbound

Xray's WireGuard client (`proxy/wireguard` of Xray-core, MPL-2.0) ported onto
[amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) v3 (MIT). An
`"amneziawg"` outbound is an ordinary outbound of the Core: TCP and UDP,
routing, balancers, observatory, stats, `controlXray` live switch, ping.
Xray's own `"wireguard"` stays untouched for plain WireGuard and WARP.

It speaks AmneziaWG up to 3.1, the latest release: 2.0 brought S3/S4,
ranges in H1-H4 and I1-I5, 3.0 header protection, content padding and
timing ranges, 3.1 random trailers and disabled cookies. Only `v3.1.*` of
amneziawg-go knows all of them: v3.0 lacks the 3.1 keys, 1.x and `master`
everything of 3.x. Configs of 1.0 and 2.0 are read by the same engine; the
keys of AmneziaWG 1.5 that v3 dropped (J1-J3, Itime) are not accepted.

## Settings

The common part is Xray's `wireguard` outbound; the rest are the keys of an
AmneziaWG `.conf` file in camelCase:

```json
{
  "protocol": "amneziawg",
  "settings": {
    "secretKey": "<base64 or hex>",
    "address": ["10.8.0.2/32"],
    "remoteDNS": ["1.1.1.1"],
    "mtu": 1280,
    "peers": [{
      "publicKey": "<base64>",
      "preSharedKey": "<base64>",
      "endpoint": "host:port",
      "keepAlive": "25-35",
      "allowedIPs": ["0.0.0.0/0", "::/0"]
    }],
    "jc": 6, "jmin": 10, "jmax": 50,
    "s1": 12, "s2": 12, "s3": 12, "s4": 12,
    "h1": "1", "h2": "2", "h3": "3", "h4": "4",
    "i1": "<r 2><b 0x...>",
    "headerProtectionKey": "<base64>",
    "rekeyAfterTime": "100-120", "rekeyTimeout": "3-7",
    "rejectAfterTime": "150-180", "keepaliveTimeout": "5-15",
    "maxHandshakeAttempts": "15-20", "contentPaddingAddition": "0-16",
    "randomTrailers": true, "disableCookies": true
  }
}
```

Ranges take a number or `"lo-hi"`. `mtu` defaults to 1280.

## Differences from Xray's WireGuard

- The device keys are set when the outbound is made, so a bad config (an
  unknown I1-I5 tag, overlapping headers, paddings too short for header
  protection) fails in `core.New` and in `testXray`, not on the first
  connection. Peers are still set on the first connection.
- No `reserved`: Xray writes it (for WARP) into bytes 1-3 of every packet and
  zeroes them on receive, where AmneziaWG keeps its magic headers.
- No kernel TUN, always Xray's own stack.
- The device's reader is woken once the keys are set
  (`netTun.WakeReader`). amneziawg-go works out the room for the S4 padding
  before it waits for a packet, and its reader starts with the device, before
  any keys: the first packet went out unpadded and the server dropped it. For
  a first DNS query in the tunnel (a domain target) that cost 5 s, the
  resolver's timeout; a datagram is never sent again at all.
- Without a domain strategy the server's domain is resolved by the system
  resolver, as other outbounds dial their servers. Xray's WireGuard asks
  Xray's DNS, which in the App goes through the proxy, that is, into the
  tunnel that is not up yet.

## Registration

Importing the package (`xray/xray.go` does) registers the config type with
Xray's object registry and the `"amneziawg"` settings with Xray's JSON
loader. That loader (`infra/conf.outboundConfigLoader`) is not exported:
`amneziawg.go` reaches it with `go:linkname` and its unexported `cache`
field with `reflect`/`unsafe`, checking the field's type, so an Xray update
that changes it fails at start and in `TestXrayLoadsTheAmneziawgProtocol`
instead of misbehaving.

## Files

- `client.go`, `bind.go`, `netstack.go`: ported from Xray, each says what
  changed.
- `conf.go`: the JSON settings and their checks.
- `config.proto` -> `config.pb.go`: run `go run .` in `protogen/` (its own
  module; protocompile and protoc-gen-go, no protoc needed).
- `tunnel_test.go`: an AmneziaWG server device on loopback in the test
  process carries TCP and UDP from a Core; other headers get no handshake;
  Xray's own WireGuard server accepts the outbound without the Amnezia keys.
