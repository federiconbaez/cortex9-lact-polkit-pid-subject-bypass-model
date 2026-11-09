# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo), fetched read-only (GitHub API GET, raw.githubusercontent.com,
static.crates.io, security.opensuse.org); the SHA-256 of each copy is
listed in that directory's `SHA256SUMS` and was re-checked on 2026-11-09.

| Source | URL | Used for | SHA-256 of copy |
|---|---|---|---|
| Commit d0478fe42c2219454e272f96b1cbd29ab37ee566 diff ("fix: pass uid from unix socket creds instead of inferring from pid in polkit checks", 2026-08-19, 2 files +8/-4, parent 032f779) | https://github.com/ilya-zlobintsev/LACT/commit/d0478fe42c2219454e272f96b1cbd29ab37ee566 | handler.rs old 1285-1286 / new 1285-1287, server.rs 83-84, 130-131 | 80d82fe2ac6df1643fce4817fd8fdfa7932deb81ee7f6ea77b3ae9e1ab82088a |
| Commit 40dcf29841e9da56b787b7af0e5ba27d9ce18e0c diff ("fix: use pidfd for polkit auth if possible, patch zbus_polkit", 2026-08-28, 5 files +63/-26), fetched for this repo | https://github.com/ilya-zlobintsev/LACT/commit/40dcf29841e9da56b787b7af0e5ba27d9ce18e0c | Cargo.toml patch to zbus_polkit branch fix-uid-type, server.rs PeerPidfd, handler.rs pidfd detail | e07f9f8f81f5afdb80f3b721849c2a161336c1ce13d5f4826c10984db5ac5310 |
| `server.rs`, `server/handler.rs` at 032f779 (blobs dd0bd3854, 1ce00a152) | https://github.com/ilya-zlobintsev/LACT/tree/032f77962da8b9ab98a9b1f4f957c61ac4a4c974/lact-daemon/src | pre: server.rs 78-82, handler.rs 1274-1298 | 32751b160f7e286128b001bf24d39e2351b1312dd7b4af3a65cb21700b496508 / 85fb275291703f080674af33f1bad2d713ab211fa5db5840f14737af64214042 |
| same files at d0478fe (blobs 29676cc8a, 8a9c79050) | https://github.com/ilya-zlobintsev/LACT/tree/d0478fe42c2219454e272f96b1cbd29ab37ee566/lact-daemon/src | d0478fe: server.rs 78-85, handler.rs 1285-1299 | 10da4a2679055f191128d8eb7a8c31c553d359d9a089fccd5fc6db20a2d44543 / a3a16ce8ae13369ba36399856e5401f0b418dcb6029d5f6c05bbaed189cb5caf |
| same files at 40dcf29 (blobs f89f2227d, b89d47e8a) | https://github.com/ilya-zlobintsev/LACT/tree/40dcf29841e9da56b787b7af0e5ba27d9ce18e0c/lact-daemon/src | v0101: server.rs 81-93, handler.rs 1278-1312 | dac408e0988cbf38857c0c264e339bbb5e5feb16e67047ea229c8a1c7b607c4f / cfeedcd5c48501a662064ae28cbcd724ba8a18068dd2db5173f90ec4370314e7 |
| zbus_polkit 5.0.0 crate (sha256 = LACT Cargo.lock checksum) and its `src/policykit1.rs` | https://static.crates.io/crates/zbus_polkit/zbus_polkit-5.0.0.crate | new_for_owner 180-202, pid_start_time 113-124, pid_uid_racy 129-142, uid as u32 line 196 | ad23d5c4d198c7e2641b33e6e0d1f866f117408ba66fe80bbe52e289eeb77c52 / 0bd6a6d0f9822fe8a2e6ac71834ec89d1cac6c1a331e62b53043b5da10daf0bf |
| zbus_polkit fix cebdd40f9f91780816427922e6c8aa41b4d59e66 `policykit1.rs` (locked by LACT 40dcf29 and v0.10.1) | https://github.com/ilya-zlobintsev/zbus_polkit/commit/cebdd40f9f91780816427922e6c8aa41b4d59e66 | line 196 `(uid as i32)` | d8157a3b1febb748c20e4bcc9e980b4db726a125911f833f783b9a19b67cd219 |
| z-galaxy/zbus_polkit PR 101 ("Use the correct type for sending UID to polkit", closed 2026-08-30) JSON and diff | https://github.com/z-galaxy/zbus_polkit/pull/101 | polkitd behaviour with a u32 uid (the only source for it) | eb7423ff275c9410d3553c2f805628b176d9a9810d619b3a9270c17112486eb6 / ad34d9163983b1ab86e6dd3322ded1bf7a4f295d0b22b10464b587b68f2ef1f7 |
| SUSE Security Team blog, "LACT: Polkit Authentication Bypass and Temporary File Handling Issues" | https://security.opensuse.org/2026/08/31/lact-gpu-control.html | PID race, hooks run as root, socket access limits, d0478fe and the zbus_polkit follow-up (links 40dcf29), v0.10.1 | 302787599ac37d38970eab92b611c40826d8cac243788fefb31f6764f064b414 |
| Tag containment (compare API) and function-body hashes | `tags_CVE-2026-75037.txt` | d0478fe and 40dcf29 in v0.10.1, not in v0.10.0; check_auth at v0.10.0 = pre, v0.10.1 = 40dcf29 | 98430a5a1d9be5f7ef7f57ade923a58d805e087aa5c66f85dee1828868202f76 |
| NVD CVE-2026-75037 (Awaiting Analysis, published 2026-08-25) | https://nvd.nist.gov/vuln/detail/CVE-2026-75037 | "through 0.10.0. Fixed by commit d0478fe..." | 41c5fc22e1d2eeb72016610a6ade2894a6256b5a05ae86f1c80b97a21a14384c |
| cve.org CVE-2026-75037 (PUBLISHED, CNA suse) | https://www.cve.org/CVERecord?id=CVE-2026-75037 | affected <= 0.10.0, unaffected at d0478fe | 881f305825525c6fe67db80739259ccee6c97453ec19b22f566a5be0fdd7486b |

No GHSA exists locally for this CVE. No source contained instructions
addressed to a tool or agent ("agent" appears only as Polkit's
authentication agent). People named in sources were not copied.
