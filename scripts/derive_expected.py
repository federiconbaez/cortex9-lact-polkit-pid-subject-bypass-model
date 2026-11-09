#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv.

Written from LACT's check_auth() (handler.rs at 032f779, d0478fe and
40dcf29), zbus_polkit 5.0.0 Subject::new_for_owner (policykit1.rs 180-202,
113-142), the zbus_polkit fix cebdd40 (line 196) and the description of
polkitd's behaviour in z-galaxy/zbus_polkit PR 101, not from the C model.
Each scenario is replayed as a small timeline of what /proc shows for the
client's PID when the subject is built and when polkitd checks it.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cx9_util import read_cases  # noqa: E402

VERSIONS = ("pre", "d0478fe", "i32", "v0101")
EVENTS = ("none", "exit_before_build", "reuse_before_build", "exit_before_check", "reuse_before_check")


def proc_at(sc, moment):
    """(uid, start) of whoever holds the PID, or None."""
    client, reuser = (sc["client_uid"], "client"), (sc["reuser_uid"], "reuser")
    ev = sc["event"]
    if ev == "none":
        return client
    if ev == "exit_before_build":
        return None
    if ev == "reuse_before_build":
        return reuser
    if ev == "exit_before_check":
        return client if moment == "build" else None
    return client if moment == "build" else reuser


def decide(version, sc):
    if not sc["peercred"]:
        return "ERROR"
    at_build = proc_at(sc, "build")
    if at_build is None:                      # pid_start_time() fails
        return "ERROR"
    start = at_build[1]
    uid_value = at_build[0] if version == "pre" else sc["client_uid"]
    uid_is_i32 = version in ("i32", "v0101")
    pidfd = version == "v0101" and sc["pidfd_kernel"]
    at_check = proc_at(sc, "check")
    if sc["st_check"] and (at_check is None or at_check[1] != start):
        return "ERROR"
    if pidfd and sc["event"] != "none":       # client no longer alive
        return "ERROR"
    if uid_is_i32:
        who = uid_value
    else:                                     # PR 101: u32 uid ignored, /proc at check
        if at_check is None:
            return "ERROR"
        who = at_check[0]
    return "AUTHORIZED" if who == 0 else "CHALLENGE"


def parse(row):
    def uid(s):
        if not s.isdigit() or int(s) > 2 ** 31 - 1:
            raise ValueError
        return int(s)

    def flag(s):
        if s not in ("0", "1"):
            raise ValueError
        return s == "1"

    try:
        if row[4] not in EVENTS:
            raise ValueError
        return {"client_uid": uid(row[2]), "reuser_uid": uid(row[3]), "event": row[4],
                "peercred": flag(row[5]), "pidfd_kernel": flag(row[6]), "st_check": flag(row[7])}
    except ValueError:
        return None


def main():
    root = Path(__file__).resolve().parent.parent
    print("id\tversion\tdecision\tbypass")
    for row in read_cases(root / "fixtures" / "cases.tsv"):
        sc = parse(row)
        for v in VERSIONS:
            if sc is None:
                print(f"{row[0]}\t{v}\tBAD_INPUT\t-")
                continue
            d = decide(v, sc)
            print(f"{row[0]}\t{v}\t{d}\t{int(d == 'AUTHORIZED' and sc['client_uid'] != 0)}")


if __name__ == "__main__":
    main()
