# cortex9-lact-polkit-pid-subject-bypass-model

Offline model of **CVE-2026-75037** (CNA SUSE, bsc#1276480): the LACT
daemon asked Polkit about a client identified only by its PID
(`Subject::new_for_owner(pid, None, None)`). A client that sends a request
and lets a privileged process take its PID before the check can be judged
as that process. Profile hooks run as root, so a bypass is root (SUSE
write-up). NVD and cve.org: "through 0.10.0. Fixed by commit d0478fe",
which passes the uid from `SO_PEERCRED`. Later, LACT's author found that
zbus_polkit 5.0.0 sends that uid as `u32` while polkitd expects `int32`,
so the uid is dropped and the race remains (z-galaxy/zbus_polkit PR 101);
40dcf29 (in v0.10.1) patches the crate and adds a `pidfd`.
Educational, deterministic, C11 checked with ASan/UBSan. **No process is
forked, no D-Bus or Polkit call is made.**

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## What is modelled (tied to the code)

| Version | Code | Subject sent |
|---|---|---|
| `pre` 032f779 (= v0.10.0 `check_auth`) | handler.rs 1285-1286 `new_for_owner(pid, None, None)` | start-time and uid read from `/proc/<pid>` when built (zbus_polkit 5.0.0 policykit1.rs 185-192, 113-142), uid as `u32` (196) |
| `d0478fe` (NVD/cve.org fix) | handler.rs 1285-1287 `Some(uid)`, server.rs 83-84 uid from `SO_PEERCRED` | uid from peer credentials, still `u32` (zbus_polkit 5.0.0 in Cargo.lock) |
| `i32` (what-if, not released) | d0478fe + zbus_polkit cebdd40 policykit1.rs 196 `(uid as i32)` | uid from peer credentials as `int32` |
| `v0101` 40dcf29 (= v0.10.1 `check_auth`) | handler.rs 1289-1300, server.rs 85-87 `PeerPidfd` | `int32` uid plus `pidfd` when available |

polkitd itself is **not** code here. Its behaviour follows the PR 101 text
("`uid` is supposed to be an i32 ... treat the request as if `uid` was not
supplied at all, and do its own `/proc` lookup"), plus two labelled
assumptions: a pidfd for a dead client fails, and (as a toggle) polkitd may
compare the start-time.

Timeline per scenario: who holds the client's PID when the subject is
built and when polkitd checks (`none`, `exit_before_build`,
`reuse_before_build`, `exit_before_check`, `reuse_before_check`).
Decision: `AUTHORIZED` if the uid polkitd decides for is 0, `CHALLENGE`
otherwise, `ERROR` if the subject cannot be built or resolved. A bypass is
`AUTHORIZED` for a non-root client.

## Differential evidence (`results/`)

`results/sweep.csv`: 160 scenarios. Bypasses: `pre` 6, **`d0478fe` 6**,
`i32` 0, `v0101` 0. On a wider grid (`tests/test_model.c`, 1,440
scenarios) `d0478fe` decides exactly like `pre` every time: with zbus_polkit
5.0.0, the commit named as the fix does not change the outcome in this
model. An `int32` uid from `SO_PEERCRED` never authorizes a non-root client.
A start-time comparison would stop a swap after the subject is built, not
one before it (the daemon then reads the new process's start-time itself).

## Build and check

```sh
sh scripts/build.sh test
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/lactpk case 1000 0 reuse_before_check 1 1 0
```

Sources: [SOURCES.md](SOURCES.md). Limits: [LIMITATIONS.md](LIMITATIONS.md).
License: Apache-2.0.
