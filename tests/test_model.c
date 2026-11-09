/* Tests for the LACT Polkit subject model. Run under ASan + UBSan with
 * -fno-sanitize-recover (scripts/build.sh test). */
#include "cx9_util.h"
#include "lact_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(c, what)                                                    \
  do {                                                                    \
    checks++;                                                             \
    if (!(c)) {                                                           \
      failures++;                                                         \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, what);               \
    }                                                                     \
  } while (0)

#define MAXCASES 64
typedef struct {
  char id[64], kind[16], hand[LK_NVERSIONS][16];
  int ok;
  lk_scenario s;
} tcase;
static tcase cases[MAXCASES];
static int ncases;

static int uid_of(const char *t, unsigned *u) {
  char *end;
  unsigned long v;
  if (!*t || strspn(t, "0123456789") != strlen(t)) return -1;
  v = strtoul(t, &end, 10);
  if (v > 2147483647UL) return -1;
  *u = (unsigned)v;
  return 0;
}

static void load_cases(const char *dir) {
  static char line[3 * CX9_FIELD_MAX];
  char path[512];
  FILE *f;
  snprintf(path, sizeof path, "%s/cases.tsv", dir);
  f = fopen(path, "r");
  CHECK(f != NULL, "open cases.tsv");
  if (!f) return;
  while (fgets(line, sizeof line, f) && ncases < MAXCASES) {
    char *fl[CX9_MAX_FIELDS];
    tcase *c = &cases[ncases];
    int k;
    if (line[0] == '#' || line[0] == '\n') continue;
    if (cx9_split_tsv(line, fl, CX9_MAX_FIELDS) != 12 || strlen(fl[0]) >= 64 || strlen(fl[1]) >= 16) {
      CHECK(0, "cases.tsv row");
      continue;
    }
    for (k = 0; k < LK_NVERSIONS; ++k) {
      CHECK(strlen(fl[8 + k]) < 16, "label length");
      snprintf(c->hand[k], sizeof c->hand[k], "%s", fl[8 + k]);
    }
    strcpy(c->id, fl[0]);
    strcpy(c->kind, fl[1]);
    memset(&c->s, 0, sizeof c->s);
    c->ok = uid_of(fl[2], &c->s.client_uid) == 0 && uid_of(fl[3], &c->s.reuser_uid) == 0 &&
            lk_parse_event(fl[4], &c->s.event) == 0 && (!strcmp(fl[5], "0") || !strcmp(fl[5], "1")) &&
            (!strcmp(fl[6], "0") || !strcmp(fl[6], "1")) && (!strcmp(fl[7], "0") || !strcmp(fl[7], "1"));
    if (c->ok) {
      c->s.peercred = fl[5][0] == '1';
      c->s.pidfd_kernel = fl[6][0] == '1';
      c->s.st_check = fl[7][0] == '1';
    }
    ncases++;
  }
  fclose(f);
  CHECK(ncases >= 20, "at least 20 fixture cases");
}

static void test_hand_labels(void) {
  int i, v, pos = 0, neg = 0, bad = 0;
  for (i = 0; i < ncases; ++i) {
    lk_result r[LK_NVERSIONS];
    if (!cases[i].ok) {
      for (v = 0; v < LK_NVERSIONS; ++v) CHECK(strcmp(cases[i].hand[v], "BAD_INPUT") == 0, cases[i].id);
      CHECK(strcmp(cases[i].kind, "bad") == 0, "only bad rows are outside the domain");
      bad++;
      continue;
    }
    for (v = 0; v < LK_NVERSIONS; ++v) {
      r[v] = lk_check_auth((lk_version)v, &cases[i].s);
      CHECK(strcmp(lk_decision_name(r[v].decision), cases[i].hand[v]) == 0, cases[i].id);
    }
    if (strcmp(cases[i].kind, "pos") == 0) {
      CHECK(lk_bypass(&cases[i].s, &r[LK_PRE]) && lk_bypass(&cases[i].s, &r[LK_D0478FE]) &&
                !lk_bypass(&cases[i].s, &r[LK_I32]) && !lk_bypass(&cases[i].s, &r[LK_V0101]),
            "pos: bypass with zbus_polkit 5.0.0, none with the i32 uid");
      pos++;
    }
    if (strcmp(cases[i].kind, "neg") == 0) {
      CHECK(r[0].decision == r[1].decision && r[1].decision == r[2].decision &&
                r[2].decision == r[3].decision && !lk_bypass(&cases[i].s, &r[0]),
            "neg: same decision everywhere, no bypass");
      neg++;
    }
  }
  CHECK(pos >= 5 && neg >= 6 && bad >= 3, "enough positive, negative and bad fixtures");
}

static void test_expected(const char *dir) {
  static char line[3 * CX9_FIELD_MAX];
  char path[512];
  FILE *f;
  int rows = 0, i;
  snprintf(path, sizeof path, "%s/expected.tsv", dir);
  f = fopen(path, "r");
  CHECK(f != NULL, "open expected.tsv");
  if (!f) return;
  while (fgets(line, sizeof line, f)) {
    char *fl[CX9_MAX_FIELDS];
    int n, v;
    if (strncmp(line, "id\t", 3) == 0) continue;
    n = cx9_split_tsv(line, fl, CX9_MAX_FIELDS);
    CHECK(n == 4, "expected.tsv row");
    if (n != 4) continue;
    for (v = 0; v < LK_NVERSIONS; ++v)
      if (strcmp(fl[1], lk_version_name((lk_version)v)) == 0) break;
    CHECK(v < LK_NVERSIONS, "known version");
    if (v >= LK_NVERSIONS) continue;
    for (i = 0; i < ncases; ++i) {
      lk_result r;
      char b[4];
      if (strcmp(cases[i].id, fl[0]) != 0) continue;
      rows++;
      if (!cases[i].ok) {
        CHECK(strcmp(fl[2], "BAD_INPUT") == 0, fl[0]);
        continue;
      }
      r = lk_check_auth((lk_version)v, &cases[i].s);
      snprintf(b, sizeof b, "%d", lk_bypass(&cases[i].s, &r));
      CHECK(strcmp(fl[2], lk_decision_name(r.decision)) == 0 && strcmp(fl[3], b) == 0, fl[0]);
    }
  }
  fclose(f);
  CHECK(rows == LK_NVERSIONS * ncases, "every case has four rows");
}

/* Exhaustive over the scenario grid with several uids. */
static void test_grid(void) {
  static const unsigned uids[] = {0, 1, 1000, 1001, 65534, 2147483647u};
  size_t a, b;
  int e, pc, pf, st, bypass_pre = 0;
  for (a = 0; a < 6; ++a)
    for (b = 0; b < 6; ++b)
      for (e = 0; e < 5; ++e)
        for (pc = 0; pc < 2; ++pc)
          for (pf = 0; pf < 2; ++pf)
            for (st = 0; st < 2; ++st) {
              lk_scenario s;
              lk_result r[LK_NVERSIONS];
              int v;
              memset(&s, 0, sizeof s);
              s.client_uid = uids[a];
              s.reuser_uid = uids[b];
              s.event = (lk_event)e;
              s.peercred = pc;
              s.pidfd_kernel = pf;
              s.st_check = st;
              for (v = 0; v < LK_NVERSIONS; ++v) r[v] = lk_check_auth((lk_version)v, &s);
              CHECK(r[LK_PRE].decision == r[LK_D0478FE].decision,
                    "with zbus_polkit 5.0.0, d0478fe decides exactly like pre");
              CHECK(!lk_bypass(&s, &r[LK_I32]) && !lk_bypass(&s, &r[LK_V0101]),
                    "an i32 uid from SO_PEERCRED never authorizes a non-root client");
              if (lk_bypass(&s, &r[LK_PRE])) {
                bypass_pre++;
                CHECK(s.reuser_uid == 0 && s.event != LK_EV_NONE, "bypass needs a root process on the PID");
                CHECK(!(s.st_check && s.event == LK_EV_REUSE_BEFORE_CHECK), "late swap caught by start-time");
              }
              if (s.event == LK_EV_NONE && s.peercred) {
                for (v = 0; v < LK_NVERSIONS; ++v)
                  CHECK(r[v].decision == (s.client_uid == 0 ? LK_AUTHORIZED : LK_CHALLENGE),
                        "no race: every version answers for the real client");
              }
              if (!s.peercred)
                for (v = 0; v < LK_NVERSIONS; ++v) CHECK(r[v].decision == LK_ERROR, "no credentials");
              if (r[LK_V0101].pidfd_sent)
                CHECK(s.event == LK_EV_NONE || r[LK_V0101].decision == LK_ERROR, "pidfd: dead client errors");
              CHECK(r[LK_PRE].uid_sent == 0 || r[LK_PRE].uid_i32 == 0, "pre sends u32");
            }
  CHECK(bypass_pre == 30, "pre bypass: 5 non-root clients x 6 swap settings");
}

static void test_adversarial(void) {
  lk_scenario s;
  lk_result r;
  lk_event e;
  memset(&s, 0, sizeof s);
  CHECK(lk_parse_event("", &e) != 0 && lk_parse_event("NONE", &e) != 0 && lk_parse_event("none ", &e) != 0,
        "event spelling is exact");
  s.client_uid = 2147483647u;
  s.reuser_uid = 0;
  s.event = LK_EV_REUSE_BEFORE_BUILD;
  s.peercred = 1;
  r = lk_check_auth(LK_V0101, &s);
  CHECK(r.decision == LK_CHALLENGE && r.uid_value == 2147483647u, "largest uid in the domain");
  r = lk_check_auth(LK_PRE, &s);
  CHECK(r.uid_value == 0 && r.decision == LK_AUTHORIZED, "pre reads the reuser's uid from /proc");
  CHECK(strlen(r.why) < sizeof r.why, "reason fits");
}

/* PRACTICE.md levels. */
static void test_practice(void) {
  lk_scenario s;
  memset(&s, 0, sizeof s);
  s.client_uid = 1000;
  s.peercred = 1;
  s.event = LK_EV_NONE;
  CHECK(lk_check_auth(LK_PRE, &s).decision == LK_CHALLENGE, "practice_level_1");
  s.event = LK_EV_REUSE_BEFORE_CHECK;
  CHECK(lk_check_auth(LK_PRE, &s).decision == LK_AUTHORIZED, "practice_level_2");
  CHECK(lk_check_auth(LK_D0478FE, &s).decision == LK_AUTHORIZED &&
            lk_check_auth(LK_D0478FE, &s).uid_value == 1000, "practice_level_3");
  CHECK(lk_check_auth(LK_I32, &s).decision == LK_CHALLENGE, "practice_level_4");
  s.pidfd_kernel = 1;
  CHECK(lk_check_auth(LK_V0101, &s).decision == LK_ERROR, "practice_level_5");
  s.pidfd_kernel = 0;
  s.st_check = 1;
  CHECK(lk_check_auth(LK_PRE, &s).decision == LK_ERROR, "practice_level_6");
  s.event = LK_EV_REUSE_BEFORE_BUILD;
  CHECK(lk_check_auth(LK_PRE, &s).decision == LK_AUTHORIZED, "practice_level_7");
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : "fixtures";
  load_cases(dir);
  test_hand_labels();
  test_expected(dir);
  test_grid();
  test_adversarial();
  test_practice();
  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
