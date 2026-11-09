/* CLI: regenerate results/ or inspect one scenario.
 *   lactpk results fixtures/cases.tsv <dir>
 *   lactpk case <client_uid> <reuser_uid> <event> <peercred> <pidfd> <st_check>
 * Pure bookkeeping: no process is forked, no D-Bus call is made. */
#include "cx9_util.h"
#include "lact_model.h"
#include <stdio.h>
#include <string.h>

static int parse_uid(const char *s, unsigned *out) {
  unsigned long v = 0;
  if (!*s) return -1;
  for (; *s; ++s) {
    if (*s < '0' || *s > '9') return -1;
    v = v * 10 + (unsigned long)(*s - '0');
    if (v > 2147483647UL) return -1;
  }
  *out = (unsigned)v;
  return 0;
}

static int parse_flag(const char *s, int *out) {
  if (strcmp(s, "0") != 0 && strcmp(s, "1") != 0) return -1;
  *out = s[0] == '1';
  return 0;
}

static int parse_scenario(char **f, lk_scenario *s) {
  memset(s, 0, sizeof *s);
  return parse_uid(f[0], &s->client_uid) || parse_uid(f[1], &s->reuser_uid) ||
                 lk_parse_event(f[2], &s->event) || parse_flag(f[3], &s->peercred) ||
                 parse_flag(f[4], &s->pidfd_kernel) || parse_flag(f[5], &s->st_check)
             ? -1
             : 0;
}

static int results(const char *cases, const char *dir) {
  static char line[3 * CX9_FIELD_MAX];
  char path[1024];
  FILE *in = fopen(cases, "r"), *out, *sw;
  static const unsigned cu[] = {0, 1000}, ru[] = {0, 1001};
  int v, a, b, e, pc, pf, st;
  if (!in) return 1;
  snprintf(path, sizeof path, "%s/cases.csv", dir);
  out = fopen(path, "w");
  if (!out) { fclose(in); return 1; }
  fputs("id,kind,version,decision,bypass,uid_type,uid_value,pidfd_sent,reason\n", out);
  while (fgets(line, sizeof line, in)) {
    char *f[CX9_MAX_FIELDS];
    lk_scenario s;
    if (line[0] == '#' || line[0] == '\n') continue;
    if (cx9_split_tsv(line, f, CX9_MAX_FIELDS) != 12) { fclose(in); fclose(out); return 1; }
    if (parse_scenario(f + 2, &s) != 0) {
      for (v = 0; v < LK_NVERSIONS; ++v)
        fprintf(out, "%s,%s,%s,BAD_INPUT,,,,,\n", f[0], f[1], lk_version_name((lk_version)v));
      continue;
    }
    for (v = 0; v < LK_NVERSIONS; ++v) {
      lk_result r = lk_check_auth((lk_version)v, &s);
      fprintf(out, "%s,%s,%s,%s,%d,", f[0], f[1], lk_version_name((lk_version)v),
              lk_decision_name(r.decision), lk_bypass(&s, &r));
      if (r.uid_sent) fprintf(out, "%s,%u,%d,", r.uid_i32 ? "i32" : "u32", r.uid_value, r.pidfd_sent);
      else fputs(",,,", out);
      cx9_csv_field(out, r.why);
      fputc('\n', out);
    }
  }
  fclose(in);
  fclose(out);
  snprintf(path, sizeof path, "%s/sweep.csv", dir);
  sw = fopen(path, "w");
  if (!sw) return 1;
  fputs("client_uid,reuser_uid,event,peercred,pidfd_kernel,st_check,pre,d0478fe,i32,v0101,"
        "bypass_pre,bypass_d0478fe,bypass_i32,bypass_v0101\n", sw);
  for (a = 0; a < 2; ++a)
    for (b = 0; b < 2; ++b)
      for (e = 0; e < 5; ++e)
        for (pc = 0; pc < 2; ++pc)
          for (pf = 0; pf < 2; ++pf)
            for (st = 0; st < 2; ++st) {
              lk_scenario s;
              lk_result r[LK_NVERSIONS];
              memset(&s, 0, sizeof s);
              s.client_uid = cu[a];
              s.reuser_uid = ru[b];
              s.event = (lk_event)e;
              s.peercred = pc;
              s.pidfd_kernel = pf;
              s.st_check = st;
              fprintf(sw, "%u,%u,%s,%d,%d,%d", s.client_uid, s.reuser_uid, lk_event_name(s.event), pc, pf, st);
              for (v = 0; v < LK_NVERSIONS; ++v) {
                r[v] = lk_check_auth((lk_version)v, &s);
                fprintf(sw, ",%s", lk_decision_name(r[v].decision));
              }
              for (v = 0; v < LK_NVERSIONS; ++v) fprintf(sw, ",%d", lk_bypass(&s, &r[v]));
              fputc('\n', sw);
            }
  fclose(sw);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[1], "results") == 0) return results(argv[2], argv[3]);
  if (argc == 8 && strcmp(argv[1], "case") == 0) {
    lk_scenario s;
    int v;
    if (parse_scenario(argv + 2, &s) != 0) {
      puts("BAD_INPUT");
      return 0;
    }
    for (v = 0; v < LK_NVERSIONS; ++v) {
      lk_result r = lk_check_auth((lk_version)v, &s);
      printf("%-8s %-10s bypass=%d", lk_version_name((lk_version)v), lk_decision_name(r.decision),
             lk_bypass(&s, &r));
      if (r.uid_sent) printf(" uid=%u(%s) pidfd=%d", r.uid_value, r.uid_i32 ? "i32" : "u32", r.pidfd_sent);
      printf("  [%s]\n", r.why);
    }
    return 0;
  }
  fprintf(stderr, "usage: %s results <cases.tsv> <dir> | case <client_uid> <reuser_uid> <event> "
                  "<peercred> <pidfd> <st_check>\n", argv[0]);
  return 2;
}
