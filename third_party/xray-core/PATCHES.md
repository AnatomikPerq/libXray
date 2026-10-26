# Xray-core, patched for libXray

Upstream: https://github.com/XTLS/Xray-core, the version `go.mod` of libXray
requires (`v1.260327.1-0.20261021115930-1b1647cd9ddf`), MPL-2.0 (see
`LICENSE`). Copied from the module cache without `*_test.go`, `testing/`,
`.github/` and `.gitignore` (it would hide `main/distro/debug/debug.go` from
git). `go.mod` of libXray points here with a `replace`, and libXray's build
scripts keep it (`build/app/build.py`; they used to drop it and fetch
upstream's module), so import paths stay upstream's and `diff -r` against the
module shows exactly what changed.

Changes, each marked `libXray patch` in the code:

- `app/router/condition.go`, `app/router/lua.go` (tested in
  `app/router/libxray_patch_test.go`): a `process` rule (and Lua's
  `FindProcess`) passes the connection's original destination when the
  target no longer has an address. Sniffing (`destOverride`) and FakeDNS put
  the domain in the target before routing, so the lookup got no destination;
  that is harmless on Windows and Linux, which look a connection up by its
  local address, but Android's `ConnectivityManager.getConnectionOwnerUid`
  needs the address the app dialed, and HYPER CLIENT's apps in traffic
  profiles never matched. `originalTarget` reads it from the session
  (`Outbound.OriginalTarget`, which the dispatcher records before sniffing).

- `app/dns/nameserver_local.go` (tested in `app/dns/libxray_patch_test.go`):
  the `localhost` server reports a name the system resolver does not know
  (`net.DNSError.IsNotFound`) as NXDOMAIN (`dns.RCodeError`), the way UDP and
  DoH servers do. Upstream returns the resolver's own error, which is neither
  an `RCodeError` nor `ErrEmptyResponse`, so the `dns` outbound answered such
  a query with nothing (the client waited out its timeout), and next to
  another server's NXDOMAIN `mergeQueryErrors` saw two different errors and
  did the same. HYPER CLIENT's desktop TUN resolves direct names through
  `localhost` since 26.10.2026: the desktop Core (`-dns network`) makes Go's
  default resolver the network's own DNS.

To update: change the version in libXray's `go.mod` `require`, run
`go mod download github.com/xtls/xray-core@<version>`, copy that module over
this directory with the same exclusions, re-apply the marked changes, keep
this file, then `go test ./app/router -run TestProcessLookupUsesTheOriginalTarget`
and `go test ./app/dns -run TestLocal` here and `go build ./... && go test ./...`
in libXray.
