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

To update: change the version in libXray's `go.mod` `require`, run
`go mod download github.com/xtls/xray-core@<version>`, copy that module over
this directory with the same exclusions, re-apply the marked changes, keep
this file, then `go test ./app/router -run TestProcessLookupUsesTheOriginalTarget`
here and `go build ./... && go test ./...` in libXray.
