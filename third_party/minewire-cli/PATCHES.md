# minewire-cli, patched for libXray

Upstream: https://github.com/dmitrymodder/minewire-cli, commit
`04457c34523f` (2026-07-15, core v26.7.3), MIT (see `LICENSE`). Only
`src/core` is kept; `go.mod` drops the gomobile tool that `src/mobile` needs.
`go.mod` of libXray points here with a `replace`, so import paths stay
upstream's and `diff -r` against a checkout shows exactly what changed.

The wire protocol is unchanged: patched clients work with any server.

Changes, each marked `libXray patch` in the code:

- `protocol.go`: `WritePacket` sends a whole frame with one `Write`;
  `frameWriter` serializes frames from the tunnel and the background noise.
  Upstream wrote the length byte by byte and the body separately, so two
  goroutines could interleave frames and desync the server, and each length
  byte left as its own one-byte TCP segment.
- `config.go`: `Config.Dial`, an optional dialer for the server connection
  (libXray binds it to the physical interface in TUN mode).
- `tunnel.go`: uses `Config.Dial` under the engine's context, so `Stop`
  aborts a pending dial; the reader loop recovers from a panic on a malformed
  frame instead of taking down the host process; a dropped session is
  redialed at once instead of on the next 3 s poll.

To update: copy upstream's `src/core` over this one and re-apply the marked
changes.
