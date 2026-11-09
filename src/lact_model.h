/* Model of how the LACT daemon builds the Polkit subject for check_auth()
 * (CVE-2026-75037) and how a PID swap changes the answer.
 *   pre      032f779 (= v0.10.0): handler.rs 1285-1286
 *            new_for_owner(pid, None, None), zbus_polkit 5.0.0
 *   d0478fe  fix named by NVD/cve.org: handler.rs 1285-1287
 *            new_for_owner(pid, None, Some(uid)), uid from SO_PEERCRED
 *            (server.rs 83-84), still zbus_polkit 5.0.0
 *   i32      what-if: d0478fe with the zbus_polkit fix cebdd40 only
 *            (policykit1.rs 196: uid sent as i32). Not a released state.
 *   v0101    40dcf29 (= v0.10.1): handler.rs 1289-1300, uid as i32 via
 *            cebdd40, plus a "pidfd" detail when SO_PEERPIDFD works
 *            (server.rs 85-87)
 * zbus_polkit 5.0.0 policykit1.rs 180-202: start-time from /proc/<pid>/stat
 * and, without a uid, the uid from /proc/<pid>/status, both read when the
 * subject is built (lines 113-142); uid inserted as u32 (line 196).
 * What polkitd does with the subject is NOT code here; it follows the text
 * of z-galaxy/zbus_polkit PR 101 and is listed in LIMITATIONS.md. */
#ifndef LACT_MODEL_H
#define LACT_MODEL_H

typedef enum { LK_PRE, LK_D0478FE, LK_I32, LK_V0101 } lk_version;
#define LK_NVERSIONS 4

/* When the client's PID changes hands, relative to the two /proc reads. */
typedef enum {
  LK_EV_NONE,               /* the client is alive throughout */
  LK_EV_EXIT_BEFORE_BUILD,  /* client gone, PID free, before new_for_owner */
  LK_EV_REUSE_BEFORE_BUILD, /* PID already taken by another process */
  LK_EV_EXIT_BEFORE_CHECK,  /* client gone after the subject was built */
  LK_EV_REUSE_BEFORE_CHECK  /* PID taken after the subject was built */
} lk_event;

typedef enum { LK_ERROR, LK_CHALLENGE, LK_AUTHORIZED } lk_decision;

typedef struct {
  unsigned client_uid, reuser_uid;
  lk_event event;
  int peercred;     /* SO_PEERCRED returned pid and uid */
  int pidfd_kernel; /* SO_PEERPIDFD works (only used by v0101) */
  int st_check;     /* assumption toggle: polkitd compares start-time */
} lk_scenario;

typedef struct {
  lk_decision decision;
  int has_identity;
  unsigned identity_uid;   /* uid polkitd decides for */
  int uid_sent, uid_i32, pidfd_sent;
  unsigned uid_value;      /* value placed in "uid" */
  char why[64];
} lk_result;

lk_result lk_check_auth(lk_version v, const lk_scenario *s);
int lk_bypass(const lk_scenario *s, const lk_result *r); /* AUTHORIZED, client not root */

int lk_parse_event(const char *s, lk_event *e);
const char *lk_event_name(lk_event e);
const char *lk_version_name(lk_version v);
const char *lk_decision_name(lk_decision d);
#endif
