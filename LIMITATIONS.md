# Limitations

- **A model, not a finding.** Nothing was reproduced against LACT, polkitd
  or a kernel. No PID race was run.
- **polkitd is described, not modelled from code.** That a `u32` uid is
  ignored and replaced by a racy `/proc` lookup, and that an `int32` uid is
  used as given (for a root caller), come only from the text of
  z-galaxy/zbus_polkit PR 101 written by LACT's author. polkit's source was
  not read. **Not verified.**
- **Two extra assumptions, labelled in the output:** a `pidfd` detail for a
  client that already exited makes polkitd fail; and, only when
  `st_check=1`, polkitd compares the start-time it was given with the
  process on the PID. Neither is verified; `st_check` is a toggle so both
  readings are visible.
- **The fix named by the CVE and the later work (discrepancy).** NVD and
  cve.org say "Fixed by commit d0478fe". d0478fe is in v0.10.1, not in
  v0.10.0, and does pass the peer uid. But LACT at d0478fe still locks
  zbus_polkit 5.0.0, whose `new_for_owner` sends the uid as `u32`
  (policykit1.rs 196). Per PR 101 and the SUSE blog that drops the uid, so
  in this model d0478fe alone decides exactly like the pre-fix code. The
  complete change in this model is 40dcf29 (2026-08-28, in v0.10.1):
  zbus_polkit patched to cebdd40 (`uid as i32`) **and** a `pidfd` detail.
  The SUSE blog links 40dcf29 as the zbus_polkit bugfix but does not
  mention the pidfd; the pidfd part comes from the commit itself.
- **`i32` is a what-if.** d0478fe with only the crate fix was never a
  published LACT state; it isolates the effect of the uid type.
- **Other references.** NVD/cve.org cite bsc#1276480; the SUSE blog links
  bsc#1274863 as the review bug. The blog URL is dated 2026-08-31 while
  its timeline says publication on 2026-08-28. Neither changes the model.
- **Who can try the race.** Per SUSE, only users who can reach the LACT
  socket (wheel, sudo or lact group). The model takes that as given.
- **Not modelled:** which requests call `check_auth` (only "a root uid is
  authorized, anything else needs authentication"), authentication agents,
  `auth_admin_keep`, PID namespaces, uid values above `2^31-1`, and the
  separate CVE-2026-75038 (temporary file).
- The grid is exhaustive for its inputs, not a proof about real timing.
