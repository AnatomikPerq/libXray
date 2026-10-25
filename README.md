# libXray

[简体中文](./readme/README.zh_CN.md)

This is a wrapper around [Xray-core](https://github.com/XTLS/Xray-core) to improve the client development experience.

# Note

1. This repository has few maintainers. If you do not report a bug or initiate a PR, your issue will be ignored.
2. This repository does not guarantee API stability, you need to adapt it yourself.
3. This repository is only compatible with the latest release of Xray-core.

# Versioning

Releases use CalVer in the form `v<YY>.<M>.<D>` (e.g. `v26.3.27` = 2026-03-27).
Because Go modules require any module with major version `>= 2` to encode the
major in its import path, every CalVer release is mirrored onto a Go-friendly
SemVer tag on the same commit:

| CalVer tag | Go-import tag |
| ---------- | ------------- |
| `v26.3.27` | `v1.260327.0` |

Go consumers should pin against the SemVer mirror:

```shell
go get github.com/xtls/libxray@v1.260327.0
```

The mirror tag is created automatically by
[`.github/workflows/release-go-mirror.yml`](./.github/workflows/release-go-mirror.yml)
on every CalVer push. Existing CalVer tags can be backfilled with
[`scripts/backfill-semver-tags.sh`](./scripts/backfill-semver-tags.sh).

# Features

## build

Compile script. It is recommended to always use this script to compile libXray. We will not answer questions caused by using other compilation methods.

depends on git and go.

By default, the build script does not clone [Xray-core](https://github.com/XTLS/Xray-core). It uses Go modules and pins Xray-core to release tag `v26.10.21` through its pseudo-version.
Pass the optional `local` argument to use an existing local checkout at `../Xray-core` through a Go module `replace`.

### Usage

```shell
# Android (min Android API level is 21)
python3 build/main.py android
python3 build/main.py android local

# Apple (gomobile or go)
python3 build/main.py apple gomobile
python3 build/main.py apple go
python3 build/main.py apple gomobile local
python3 build/main.py apple go local

# Linux
python3 build/main.py linux
python3 build/main.py linux local

# Windows
python3 build/main.py windows
python3 build/main.py windows local

```

Builds snapshot and restore `go.mod` and `go.sum` on success or failure by default.
Pass `--no-snapshot` to skip both the snapshot and restoration. Before initializing
Go dependencies, the script deletes existing `go.mod` and `go.sum` and creates a
fresh module. The resulting files are retained even if the build fails.
This option is supported by every target
and can be combined with `local` in either order:

```shell
python3 build/main.py android --no-snapshot
python3 build/main.py apple go local --no-snapshot
```

Gomobile builds
resolve `latest` by default; set `LIBXRAY_GOMOBILE_VERSION` to select a Go module
version. Both `gomobile` and `gobind` use that resolved version.

Linux and Windows builds also produce `bin/xray` or `bin/xray.exe`. This
session Core accepts only:

```shell
xray run [-dns <IP:port> -interface <name>] -config <xray.json>
         [-config-sha256 <hex>] [-error-file <path>] [-stop-file <path>]
```

`-config` points directly to the Xray JSON configuration. `-dns` and
`-interface` go together: in TUN mode they install a process-wide resolver
bound to the physical interface, so the Core's own lookups cannot loop into
the tunnel. A Core without a tunnel (system proxy mode) passes neither and
follows normal OS routing. `-dns` must be an IP endpoint.

The HYPER CLIENT fork hardens the Core for running elevated from files in a
directory every process of the user can write:

- `-config-sha256` makes the Core refuse a config whose SHA-256 differs; a
  non-elevated process cannot change the arguments once UAC started the Core.
- The `-error-file` and the log files named in the config are opened by the
  Core first and refused if any part of their path is redirected (junction,
  symlink). The handles stay open for the life of the process, which also
  pins the paths against renames.
- `-stop-file` stops the Core gracefully once the file appears, so the App can
  end an elevated Core without another UAC prompt. The Core only checks the
  file and never writes or deletes it.

The optional `-error-file` also writes command failures to a UTF-8 file before
exiting, preserving the same error printed to stderr. The file is cleared before
running; a successful run leaves it empty. Its parent directory must exist.
Callers launching an elevated Core should create the file first under their own
account so they retain read access. This is an error-return channel, not Xray's
access/error log configuration, and it does not add a separate validation pass.
Applications using these options must bundle a desktop Core built with their
support.

> [!WARNING]
> **Use only one Go runtime per process.** Go does not support loading multiple
> independently built Go runtimes into one process. Every native libXray
> artifact embeds a Go runtime, whether it is produced through cgo or gomobile.
> Do not load libXray together with another independently built Go, cgo, or
> gomobile library in the same executable or process. Doing so can fail during
> build, link, or load, or crash during runtime initialization before
> application code runs.
> If one process needs Go packages from several libraries, include those
> packages in the same Go build or `gomobile bind` invocation and produce one
> native artifact so they share a runtime. Merely repackaging or merging
> independently built frameworks, archives, AARs, shared libraries, or DLLs is
> not sufficient. Separate OS processes may each load one Go runtime, so apply
> this rule independently to each process. See
> [Go #18976](https://github.com/golang/go/issues/18976#issuecomment-308505600),
> [golang/go#15956](https://github.com/golang/go/issues/15956#issuecomment-373709423),
> and [libXray #116](https://github.com/XTLS/libXray/issues/116).

### Android

use [gomobile](https://github.com/golang/mobile) .

### iOS && macOS

#### 1. use gomobile

Need "iOS Simulator Runtime".

This is the best choice for general scenarios. The cross-platform single-runtime
restriction above still applies when linking other Go-based libraries.

Supports iOS, iOSSimulator, macOS, macCatalyst.

But it is not possible to set the minimum macOS version, which will cause some warnings when compiling. And it does not support tvOS.

#### 2. use cgo

Need "iOS Simulator Runtime" and "tvOS Simulator Runtime".

Support more compilation options, output c header files.

This works well when you use ffi for integration. For example, integration with swift, kotlin, dart.

Support iOS, iOSSimulator, macOS, tvOS.

The product `LibXray.xcframework` contains **module.modulemap**. When using
Swift, import it as module `LibXray`.

### Linux

depend on gcc and g++.

### Windows

Depends on gcc and g++ in `PATH`.

Native amd64 and arm64 builds are supported. The release workflow builds each
architecture on its matching GitHub-hosted Windows runner.

## API

libXray exposes a single structured entrypoint:

```go
func Invoke(requestJSON string) string
```

The C export is:

```c
char* CGoInvoke(char* requestJSON);
void CGoFree(char* value);
```

`CGoInvoke` allocates its response. The caller must release every non-null
response with `CGoFree`; do not use a platform allocator directly.

The request is a JSON object:

```json
{
  "apiVersion": 3,
  "method": "runXray",
  "payload": {
    "xrayJson": "{\"outbounds\":[...]}"
  }
}
```

The response is a JSON object:

```json
{
  "success": true,
  "data": {},
  "error": ""
}
```

Design notes:

1. Invoke accepts only `apiVersion: 3`; the API version remains fixed at 3.
   Contract changes require synchronized consumers and documentation within
   that version. Xray configurations are passed as UTF-8 JSON text in
   `xrayJson`; libXray does not read configuration file paths.
2. A top-level `env` field is ignored and has no effect. Xray-core runtime
   environment options belong in the root `env` object of the Xray config.
3. `SetTunFd` has been removed. When the fd is only known at runtime, write
   `xray.tun.fd` into the Xray config root `env` object before calling
   `runXray`.
4. `countGeoData` is not backed by an Xray config, so its `datDir` is passed in
   the method payload.
5. The complete UTF-8 encoded Invoke request and response JSON envelopes are
   limited to 16 MiB. If either limit is exceeded, Invoke returns a failure
   response with `success: false`, `data: null`, and a size-limit error.
6. `convertShareLinksToXrayJson` validates each parsed outbound with the current
   Xray-core config builder. Invalid outbounds are omitted, and the method fails
   if none remain. Validation does not create or start an Xray instance.
   Xray JSON input is treated as a node source: only its root `outbounds` are
   retained, and all other root fields are ignored. The response contains only
   fields supported by libXray share links; unsupported and generated empty
   fields are omitted. Opaque XHTTP `extra` and FinalMask mask `settings` JSON
   remain unchanged.
   Every successful response contains only the projected `outbounds` list.
   Its optional `age.secretKey` decrypts official age ASCII armor in memory
   before the existing parser runs. Plaintext input remains unchanged.
7. Xray-core keeps its system dialer DNS client and outbound manager in
   process-wide state. `pingBatch`, `testXray`, and their exported Go
   entrypoints take the managed lifecycle lock and reject an active `runXray`
   instance before loading/building config.
   A batch holds the lock through all workers and temporary-core close. This
   also serializes these operations with one another. Instances
   created outside the managed APIs are not detected or restored; callers
   requiring overlap with them must still use separate processes.
8. `decodeSubscriptionText` returns the complete plaintext after optional Age
   decryption. It does not parse subscription formats, project outbounds or
   construct an Xray instance; callers own classification and validation.

Supported methods:

```text
getFreePorts
decodeSubscriptionText
convertShareLinksToXrayJson
convertXrayJsonToShareLinks
generateAgeKeyPair
countGeoData
pingBatch
testXray
runXray
stopXray
xrayVersion
getXrayState
controlXray
startMinewire
stopMinewire
minewireState
killSwitchState
liftKillSwitch
resolveHost
startNetworkReport
networkReportState
cancelNetworkReport
```

The last ten methods belong to the HYPER CLIENT fork; see [control](#control),
[minewire](#minewire), [kill switch](#kill-switch) and
[network report](#network-report).

## control

`controlXray` changes a running desktop Core without restarting it, so a node
switch does not cost another UAC prompt for the elevated TUN Core.

Xray's gRPC API has no authentication, and whoever reaches it can add inbounds
or reroute the traffic of an elevated process. The Core therefore never opens a
raw API listener (`api.listen` stays empty). The App adds a loopback SOCKS5
inbound with a random per-session password and routes that inbound tag to the
`api` outbound as the first routing rule. `controlXray` dials the API through
that inbound:

```json
{
  "server": "127.0.0.1:43127",
  "username": "app",
  "password": "<random per session>",
  "timeoutSeconds": 5,
  "operations": [
    {"op": "removeRule", "tag": "app-minewire-bypass"},
    {"op": "removeOutbound", "tag": "proxy"},
    {"op": "addOutbound", "outbound": {"tag": "proxy", "protocol": "vless"}},
    {"op": "addRules", "routing": {"rules": [...], "balancers": [...]}}
  ]
}
```

`server` must be a loopback IP literal. Operations run in order and stop at the
first failure; the error names the failing index so the caller can fall back to
a full restart. Removing the default (first) outbound leaves Xray without one
until the next `addOutbound`, which then becomes the default. `addRules`
without `append` REPLACES every rule and balancer in one step (Xray's
`ReloadRules`); the new routing must therefore keep the rule that routes the
control inbound to `api`. With `"append": true` the rules are added after the
current ones. `domainStrategy` is never changed.

## minewire

`startMinewire` (`serverAddress`, `password`, `mode`, optional `localPort`,
`interface` and `logFile`) starts one embedded
[minewire](https://github.com/dmitrymodder/minewire-cli) engine and returns
its loopback SOCKS5 port; Xray reaches it as an ordinary `socks` outbound.
`interface` binds the engine's connection to the server to that network
interface, as `sockopt.interface` does for Xray, so a desktop TUN does not
capture it; if the interface is missing the engine dials unbound. The engine
carries TCP only: SOCKS UDP is refused, so DNS through it must use TCP. Several engines may run at once, keyed by that port, so a
balancer can hold more than one minewire node and a node switch can start the
new engine before stopping the old one. An engine accepts connections
immediately but connects in the background: poll `minewireState`, which lists
every engine, for `connected`. `stopMinewire` takes an optional `localPort`
(0 stops all) and is idempotent. Pass an already resolved server address,
because DNS may depend on the tunnel that is not up yet. Optional `logFile`
appends the engine's logins, drops and errors (and yamux's keepalive
failures) to that file, each line tagged with the engine's port, rotating it
to `<logFile>.1` at 1 MiB. `connected` in `minewireState` turns false as soon
as the session drops, not only after the next successful login.

The engine is a patched copy of upstream's `src/core` in
`third_party/minewire-cli`, wired in with a `replace` in `go.mod`; the wire
protocol is unchanged. `third_party/minewire-cli/PATCHES.md` lists the
changes.

## kill switch

The desktop TUN Core takes `-kill-switch` (with optional `-kill-switch-lan`,
`-kill-switch-app <path>` and `-kill-switch-persistent`). Before Xray starts it
installs Windows Filtering Platform filters that block every connection in
and out, both IP versions, except: the Core and the `-kill-switch-app`
executable, loopback, DHCP and IPv6 neighbor discovery, the TUN adapter once
Xray has created it, and with `-kill-switch-lan` private, link-local and
multicast networks (DNS to them stays blocked). The filters live in a WFP
session that is not dynamic, so they outlive the Core: a Core that crashes
leaves the machine blocked instead of leaking. `-kill-switch-persistent` also
keeps them across a reboot. Package `killswitch` holds the filters; the plan
is plain data and tested without WFP.

They are removed only on purpose. The App's stop file decides: empty (a
disconnect) lifts them, `restart` (another Core follows) keeps them, and a
signal keeps them too. The filters grant the user who ran the Core read and
delete rights, so the unelevated App calls `killSwitchState` (`{"engaged":
bool}`) and `liftKillSwitch` itself, without another UAC prompt.
`HyperClientCore unblock`, run elevated, is the fallback when the App's user
may not (an administrator elevated the Core with other credentials). Other
platforms report `engaged: false`, lift nothing, and refuse `-kill-switch`.
`killSwitchState` also returns `session` (`bootedAt` in Unix milliseconds and
`logon`), so the App can tell a block left in this session from one left
before the user logged off: Windows' fast startup keeps the boot time across a
shutdown, not the logon.

`resolveHost` (`host`, optional `timeoutSeconds`) resolves a name with Go's own
resolver, IPv4 first. The queries leave from the calling process; the system
resolver would hand them to Windows' DNS Client service, which the kill switch
blocks outside the tunnel, so the App could not resolve a minewire server while
it reconnects.

## network report

Package `netreport` measures how the network treats DNS, TLS, UDP and the
networks VPN servers rent from, for a report the user hands to a VPN provider.
Every probe binds to the requested interface (`netbind`, as minewire uplinks
do), never uses the environment's proxy, and takes target addresses from DoH,
so a running tunnel or a spoofed DNS answer does not hide what happens on the
way to the real address.

A run takes one to three minutes, so it runs in the background:

```json
{"method": "startNetworkReport", "payload": {
  "interface": "Ethernet 4", "systemDns": ["10.0.0.1"],
  "sections": ["network", "dns", "sites", "hosting", "udp"],
  "sites": ["example.org"], "maxBytes": 262144, "bypass": true}}
```

returns `{"id": "..."}`; `networkReportState` (`id`) returns `running`,
`progress` (`section`, `done`, `total`), `error` and the `report` so far;
`cancelNetworkReport` (`id`) stops it and keeps what finished. One run at a
time; finished runs are kept for ten minutes. All payload fields are optional:
an empty interface uses the default route, `systemDns` replaces the
interface's resolvers (Android and iOS hide them from Go), no sections means
all.

The report (`version` 1) holds `network` (adapter kind, external IPv4/IPv6
with AS and holder from Team Cymru's DNS zone, else RIPEstat), `dns` (each
resolver over UDP from fresh sockets: loss, forged answers judged against DoH,
injection seen as a second answer, egress holder for interception), `sites`,
`hosting`, `sni`, `udp` (STUN, QUIC handshakes) and `facts`. With `bypass`
a refused name is retried with the ClientHello in two TCP segments (`split`)
and re-framed into small TLS records the way Xray's `freedom` fragment
"tlshello" does (`fragment`, then the same request over it:
`fragmentTransfer`); only application-level cutting, no packet tricks. Statuses are in
`netreport/report.go`; the catalog of targets is `netreport/catalog.json`.
Live run: `go test ./netreport -run TestLive -netreport.live
-netreport.iface "<interface>" [-netreport.dns <resolvers>]
-netreport.out report.json -v`.

## controller

### Socket protect

Used to solve the socket protect problem on Android.

### DNS resolver

Android may expose a loopback DNS server to Go's resolver while a VPN is
active. Call `SetDNS` before `runXray` to make Go use the DNS server selected by
the VPN configuration and protect the DNS socket from the VPN tunnel. The
server must be an IP endpoint with a port, such as `8.8.8.8:53` or
`[2001:4860:4860::8888]:53`.

Call `ResetDNS` after Xray has stopped. These APIs are available only in the
Android artifact and change the process-wide Go resolver.

```java
LibXray.setDNS(controller, "8.8.8.8:53");
LibXray.invoke(runXrayRequest);

// Later, when stopping the core:
LibXray.invoke(stopXrayRequest);
LibXray.resetDNS();
```

### Process finder (per-app routing)

`ConnectivityManager.getConnectionOwnerUid()` is API 30+. On older Android
libXray falls back to parsing `/proc/net/{tcp,udp}{,6}` in pure Go.

Usage (Java/Kotlin):

```java
ProcessFinder finder = new ProcessFinder() {
    @Override
    public long findProcessByConnection(String network, String srcIP, long srcPort,
                                         String destIP, long destPort) {
        return -1; // return UID or -1
    }
};
LibXray.registerProcessFinder(finder, Build.VERSION.SDK_INT);
```

A `process` rule then matches the UID as a string (`"process": ["10123"]`).
Sniffing and FakeDNS replace a connection's target with its domain before
routing, and upstream Xray-core passed no destination to the finder then, so
`getConnectionOwnerUid` found nothing; libXray builds against a patched copy
of Xray-core in `third_party/xray-core` (a `replace` in `go.mod`) that passes
the original destination. `third_party/xray-core/PATCHES.md` lists the change
and how to move to another Xray-core version.

## geo

### count

Read geo files and count the categories and rules.

## main

Download geosite.dat and geoip.dat and count them.

## memory

Only executed on iOS, GC is initiated once a second. This can alleviate memory pressure on iOS.

## nodep

### file

Write data to a file.

### measure

Speed ​​test the Xray configuration.

### port

`getFreePorts` returns distinct free TCP ports on localhost. Its payload accepts
`count` and an optional `excludePorts` list of caller-reserved port numbers:

```json
{
  "apiVersion": 3,
  "method": "getFreePorts",
  "payload": {"count": 2, "excludePorts": [18587, 9000]}
}
```

The response keeps the existing `data.ports` integer array. Omit `excludePorts`
or pass an empty list for no exclusions; duplicates have no additional effect.
Excluded ports must be between 1 and 65535. Negative or impossible counts fail;
zero returns no ports. The Go entrypoint is
`nodep.GetFreePorts(count int, excludePorts []int)`; pass `nil` for no exclusions.

Listeners remain open during selection to avoid duplicates or repeatedly picking
an excluded port, and close before the function returns, including on failure.
The returned ports are therefore candidates, not reservations: another process
can claim them before the caller binds. This checks TCP only, not UDP.

## share

libXray stores outbound names in `tag`. `sendThrough` keeps its native Xray
meaning as the local bind address.

### generate_share

Convert Xray JSON to VMessAEAD / VLESS share links following
[Xray-core discussion #716](https://github.com/XTLS/Xray-core/discussions/716).
Hysteria2, SS, SOCKS and Trojan share links are also supported. VMess always generates
an AEAD URI, not the legacy QR-code format.

Outbounds without a supported share-link format are skipped. Conversion fails
if no share links can be generated.

### parse_share

Parse VMessAEAD / VLESS, Hysteria2, SS, SOCKS and Trojan share links into Xray JSON.
Legacy VMessQrCode links (`vmess://Base64(JSON)`) are not supported.

Xray JSON node input and Base64 / Age subscription wrappers remain supported.
Clash/Mihomo configurations remain unsupported.

Hysteria2 accepts `hysteria2://` and `hy2://` using the
[official URI scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/):
optional authentication, default port 443, IPv6, SNI, Salamander obfuscation,
multi-port authorities and fragment names. Export uses `hysteria2://`.
Port hopping uses Core's `finalmask.udp` with both local and remote interval
hopping (30 seconds by default; `hop-interval` must be at least 5 seconds).
Legacy `ports` / `mport` queries are accepted and exported as authority ports.
Legacy `up` / `down` values are imported as client-local QUIC tuning, not exported.

TLS is mandatory. `insecure=true` / `allowInsecure=true` and `pinSHA256` are
rejected: the bundled Core cannot preserve those Hysteria TLS semantics.
Explicit Xray `fp`, `alpn`, `ech`, `pcs` and `vcn` extensions retain their Xray
meaning. Export rejects TLS/mask settings that cannot be represented, rather
than silently dropping security or obfuscation. Client-local QUIC tuning is
not part of the URI. Realm and Gecko are not supported. Hopping requires a
direct UDP socket; this does not add hopping support over chained proxies.

VMessAEAD / VLESS field mappings follow the
[Xray share-link proposal](https://github.com/XTLS/Xray-core/discussions/716)
where supported by the bundled Core:

- mKCP `mtu` and `tti` are preserved in both directions. Omitted values use
  Core defaults; Core validates their ranges. Legacy KCP `seed` and `headerType`
  are not imported or exported.
- XHTTP `extra` keeps its complete JSON content, including nested settings.
  `fm` carries FinalMask masks and all Core-supported `quicParams` fields.
- TLS `ech`, `pcs`, `vcn` and REALITY `pbk`, `sid`, `pqv`, `spx` are preserved
  alongside `sni`, `fp` and TLS `alpn`. An omitted `sni` uses the remote host,
  not the WebSocket HTTP host.
- Native transport aliases retain their settings when exported. RAW/TCP links
  use `type=tcp`; query values use percent-encoded spaces.
- gRPC supports `gun` and `multi`. The bundled Core does not support `guna`
  mode or the removed HTTP/QUIC transports; these are not silently substituted.

#### Parsing result

`convertShareLinksToXrayJson` has one response shape. Its payload contains
`text` and optional `age`. Every successful conversion returns
`data: {"outbounds":[...]}`. There is no statistics or nested config wrapper.

Invalid individual elements are skipped without discarding other valid nodes.
The list preserves source order and includes only projected, buildable outbounds.
No per-node hash comparison, deduplication or failed-node counting is performed.

No usable nodes, an unrecognized format, a malformed document, an invalid
container or a decryption failure returns `success: false` with `data: null`.
Error text never includes rejected candidates or decrypted subscription text.
Callers must not import/replace a subscription when no usable nodes remain.

### decodeSubscriptionText

Returns the complete subscription text, including full Xray JSON objects or
arrays and their DNS, routing, balancers and unknown fields. This method only
unwraps Age armor: unencrypted text, including URI lists and Base64 strings,
is returned exactly as supplied. It does not validate JSON or decode Base64.

```json
{
  "apiVersion": 3,
  "method": "decodeSubscriptionText",
  "payload": {
    "text": "-----BEGIN AGE ENCRYPTED FILE-----\n...",
    "age": {
      "secretKey": "AGE-SECRET-KEY-1..."
    }
  }
}
```

Success returns `data: {"text": "<complete plaintext>"}`; the `text` field is
present even for empty text. Errors return `data: null` and the existing Age
key, armor, decryption or plaintext-size error. Both unencrypted and decrypted
plaintext are limited to 16 MiB of UTF-8 bytes. The complete Invoke request and
encoded response retain their separate 16 MiB limits, so envelope or escaping
overhead can reject text below the plaintext limit. The Go helper is
`share.DecodeSubscriptionText(text, secretKey)`.

The caller must classify the returned text before importing nodes or storing a
complete configuration. This method does not create a temporary Core and can
be called while a managed instance is running.

### age-encrypted subscriptions

`decodeSubscriptionText` and `convertShareLinksToXrayJson` accept an optional
native age secret key. Only
X25519 (`AGE-SECRET-KEY-1...`) and ML-KEM-768 + X25519 hybrid
(`AGE-SECRET-KEY-PQ-1...`) identities are accepted. Recognized age armor is
decrypted in memory and limited to 16 MiB of plaintext.

```json
{
  "apiVersion": 3,
  "method": "convertShareLinksToXrayJson",
  "payload": {
    "text": "-----BEGIN AGE ENCRYPTED FILE-----\n...",
    "age": {
      "secretKey": "AGE-SECRET-KEY-1..."
    }
  }
}
```

Generate a new keypair with `keyType` set to `x25519` or `hybrid`. An omitted
`keyType` defaults to `x25519`. The `hybrid` option matches Mihomo
`age keygen-pq` and produces an `AGE-SECRET-KEY-PQ-1...` identity with an
`age1pq1...` recipient.

```json
{
  "apiVersion": 3,
  "method": "generateAgeKeyPair",
  "payload": {
    "keyType": "x25519"
  }
}
```

The response contains both `secretKey` and `publicKey`. The integrating
application must persist the pair and send only `publicKey` as
`X-Age-Public-Key`. libXray does not perform the subscription HTTP request,
persist keys, or add headers. Applications must never send the secret key over
HTTP or log secret keys or decrypted subscription text. Configuration
persistence belongs to the integrating application.

### xray_json

Some tools used to parse shared links.

## xray

### pingBatch

Tests multiple outbound configurations concurrently in one temporary Xray
instance. Each `xrayJson` string is parsed only for its `outbounds`; all other
root fields are ignored. The target outbound is selected by `outboundTag`, then
by the `proxy` tag, and finally by the first outbound.

```json
{
  "apiVersion": 3,
  "method": "pingBatch",
  "payload": {
    "configs": [
      {
        "xrayJson": "{\"outbounds\":[...]}"
      },
      {
        "xrayJson": "{\"outbounds\":[...]}",
        "outboundTag": "media"
      }
    ],
    "timeout": 5,
    "url": "https://cp.cloudflare.com/",
    "locationUrl": "https://ip-check-perf.radar.cloudflare.com/"
  }
}
```

Each request accepts at most five configurations and tests all accepted
configurations concurrently. Requests containing more than five configurations
fail before any configuration is tested.

The top-level response succeeds when the batch itself was accepted. Each item
has its own result; `delay` is `10000` for an error and `11000` for a timeout.
`delay` is always present, including a successful zero-millisecond result.
The result array has the same length and order as the input config array.
Outbound dependencies referenced by `streamSettings.sockopt.dialerProxy` are
included automatically. Xray-core rejects the removed `proxySettings` field.

`locationUrl` is optional and must be an absolute HTTP(S) URL. When omitted,
no location request is made and no location fields are returned. When supplied,
each prepared item sends its latency HEAD and then its location GET using the
same client forced through that item's selected outbound and dependencies.
Each request has the configured timeout (so an item may take up to twice it).
Location time is not included in `delay`, and the two results are independent:
`success`, `delay` and `error` describe latency only; a location failure does not
invalidate a successful latency result, and GET is still attempted after a
latency failure.

A successful GET adds the unmodified response body as the `locationJson`
string. The App owns JSON parsing and provider-specific field handling. The
provider must return HTTP 200 and at most 64 KiB; transport or body-read
failures instead add `locationError`. Errors do not echo the URL, credentials
or response body. Invalid outbound configs retain their ordinary per-item
failure and do not perform either request.

This fork keeps the `locationUrl` probe, which upstream removed: the App
shows each node's flag from it.

### testXray

Loads the supplied JSON text and constructs a temporary Xray instance. The
payload contains only `xrayJson`; success returns `data: {}`:

```json
{
  "apiVersion": 3,
  "method": "testXray",
  "payload": {
    "xrayJson": "{\"outbounds\":[...]}"
  }
}
```

The Go entrypoint `TestXray` calls `newXrayInstance` (`core.LoadConfig` followed
by `core.New`) and closes the successfully constructed instance before returning.
It never calls `Start` or publishes a managed instance. Core construction errors,
including invalid routing matchers and missing balancers, and close errors are
returned through the normal error response.

This is not a sandbox. Builders and constructors may read local GeoData and
certificates, apply `env`, replace process-global logging/DNS state, create log
files, or initialize protocol-specific resources and background tasks. Process
state is not restored. In particular, WireGuard can acquire a TUN during
construction and VLESS reverse can schedule background work. The current Core
does not return its partial instance when construction fails, so libXray cannot
close that partial instance. Core-managed geodata cron does not run without
`Start`, although its asset declarations still check local files.

Callers may provide a minimal configuration or remove App-managed fields from a
disposable validation copy; libXray applies no App-specific filtering. Only the
supplied configuration is checked. Success establishes instance construction and
close, not listener/TUN startup, system permissions, or network connectivity.
Callers must handle actual startup failures.

### runXray

Starts the managed Xray instance from the supplied JSON text. Use `stopXray`
to stop that instance. `runXrayFromJson` is no longer a separate method.

### metrics

Refer to the following configuration:

```json
{
  "metrics" : {
    "listen": "127.0.0.1:49227"
  },
  "policy" : {
    "system" : {
      "statsInboundDownlink" : true,
      "statsInboundUplink" : true,
      "statsOutboundDownlink" : true,
      "statsOutboundUplink" : true
    }
  },
  "stats" : {}
}
```

The metrics server exposes the Xray runtime counters through HTTP. For example,
when `listen` is `127.0.0.1:49227`, read:

```text
http://localhost:49227/debug/vars
```

Metrics only needs the `listen` field in this wrapper. Query `/debug/vars`
directly with an HTTP client instead of going through libXray. Counters belong
to the current Xray instance; libXray does not sample or persist traffic.

### validation

Verify the Xray configuration.

### xray

Start and stop Xray instances.

# Credits

[Project X](https://github.com/XTLS/Xray-core)

[VMessPing](https://github.com/v2fly/vmessping)

[FreePort](https://github.com/phayes/freeport)

[MetaCubeX age](https://github.com/MetaCubeX/age) (BSD 3-Clause)

# License

This repository is based on the MIT License.
