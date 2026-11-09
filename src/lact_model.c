#include "lact_model.h"
#include <stdio.h>
#include <string.h>

/* The two processes that can sit on the PID. Start times are opaque. */
typedef struct {
  int present;
  unsigned uid;
  unsigned long long start;
} proc_t;

enum { CLIENT_START = 1000, REUSER_START = 2000 };

static proc_t occupant(const lk_scenario *s, int at_check) {
  proc_t p = {1, s->client_uid, CLIENT_START};
  switch (s->event) {
  case LK_EV_NONE: break;
  case LK_EV_EXIT_BEFORE_BUILD: p.present = 0; break;
  case LK_EV_REUSE_BEFORE_BUILD: p.uid = s->reuser_uid; p.start = REUSER_START; break;
  case LK_EV_EXIT_BEFORE_CHECK: if (at_check) p.present = 0; break;
  case LK_EV_REUSE_BEFORE_CHECK:
    if (at_check) { p.uid = s->reuser_uid; p.start = REUSER_START; }
    break;
  }
  return p;
}

static lk_result fail(lk_result r, const char *why) {
  r.decision = LK_ERROR;
  r.has_identity = 0;
  snprintf(r.why, sizeof r.why, "%s", why);
  return r;
}

lk_result lk_check_auth(lk_version v, const lk_scenario *s) {
  lk_result r;
  proc_t build = occupant(s, 0), check = occupant(s, 1);
  unsigned long long start;
  memset(&r, 0, sizeof r);
  /* handler.rs: ctx.pid / ctx.uid come from SO_PEERCRED at accept time */
  if (!s->peercred) return fail(r, v == LK_PRE ? "no client PID" : "no client UID");
  /* zbus_polkit 180-188: start_time = pid_start_time(pid) (/proc/<pid>/stat) */
  if (!build.present) return fail(r, "pid_start_time: no such process");
  start = build.start;
  r.uid_sent = 1;
  if (v == LK_PRE) {
    r.uid_value = build.uid;           /* 189-192: pid_uid_racy(pid) */
  } else {
    r.uid_value = s->client_uid;       /* Some(uid) from peer credentials */
  }
  r.uid_i32 = v == LK_I32 || v == LK_V0101; /* cebdd40 line 196 */
  /* 40dcf29 handler.rs 1294-1299: pidfd detail if ctx.pid_fd is Some */
  r.pidfd_sent = v == LK_V0101 && s->pidfd_kernel;

  /* polkitd, per PR 101: a u32 "uid" is treated as absent and the uid is
   * looked up from /proc at check time; an i32 "uid" is used as given. */
  if (s->st_check && (!check.present || check.start != start))
    return fail(r, "start-time mismatch (assumption)");
  if (r.pidfd_sent && s->event != LK_EV_NONE)
    return fail(r, "pidfd: client process gone (assumption)");
  if (r.uid_i32) {
    r.identity_uid = r.uid_value;
  } else {
    if (!check.present) return fail(r, "polkitd /proc lookup: no such process");
    r.identity_uid = check.uid;
  }
  r.has_identity = 1;
  r.decision = r.identity_uid == 0 ? LK_AUTHORIZED : LK_CHALLENGE;
  strcpy(r.why, r.uid_i32 ? "uid from subject" : "uid from /proc at check");
  return r;
}

int lk_bypass(const lk_scenario *s, const lk_result *r) {
  return r->decision == LK_AUTHORIZED && s->client_uid != 0;
}

static const char *EV[] = {"none", "exit_before_build", "reuse_before_build", "exit_before_check",
                           "reuse_before_check"};

int lk_parse_event(const char *s, lk_event *e) {
  int i;
  for (i = 0; i < 5; ++i)
    if (strcmp(s, EV[i]) == 0) {
      *e = (lk_event)i;
      return 0;
    }
  return -1;
}
const char *lk_event_name(lk_event e) { return EV[e]; }
const char *lk_version_name(lk_version v) {
  static const char *n[] = {"pre", "d0478fe", "i32", "v0101"};
  return n[v];
}
const char *lk_decision_name(lk_decision d) {
  static const char *n[] = {"ERROR", "CHALLENGE", "AUTHORIZED"};
  return n[d];
}
