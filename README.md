# F16

Bug report: any authenticated Spark user can permanently disable another user's Lightning receive for a specific BOLT11 invoice. One RPC call, no special access.

- `F16.md` — the writeup
- `poc/` — a Go test that reproduces it against the local cluster

The bug is in `preimage_share_flow_handler.go:185-196`. Three existing
behaviours combine into the exploit; the writeup walks through them.
