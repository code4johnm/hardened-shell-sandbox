/*
 * hss-status - print the confinement state of the current process.
 *
 * DEFENSIVE TOOL ONLY. Read-only: it changes nothing.
 *
 *   hss-status                  human-readable report
 *   hss-status --require        exit 1 unless no_new_privs=1, seccomp filter
 *                               mode and empty capability sets
 *
 * Run it as the command under sandbox-run to confirm the layers reached
 * the child, e.g.  seccomp/sandbox-run --mode strict -- tools/hss-status
 *
 * Reports: no_new_privs, seccomp mode and filter count, dumpable, the five
 * capability sets, the AppArmor label, the cgroup v2 path, and the soft/hard
 * values of the rlimits sandbox-run manages.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

#include "../seccomp/hss.h"

static void print_file_line(const char *label, const char *path)
{
	char buf[512];
	FILE *f = fopen(path, "re");

	if (!f) {
		printf("%-16s (unavailable: %s)\n", label, strerror(errno));
		return;
	}
	if (fgets(buf, sizeof buf, f)) {
		buf[strcspn(buf, "\n")] = '\0';
		printf("%-16s %s\n", label, buf);
	} else {
		printf("%-16s (empty)\n", label);
	}
	fclose(f);
}

static void print_cgroup(void)
{
	char buf[512];
	FILE *f = fopen("/proc/self/cgroup", "re");

	if (!f) {
		printf("%-16s (unavailable: %s)\n", "cgroup", strerror(errno));
		return;
	}
	while (fgets(buf, sizeof buf, f)) {
		buf[strcspn(buf, "\n")] = '\0';
		/* cgroup v2 unified entry is "0::/path". */
		if (!strncmp(buf, "0::", 3))
			printf("%-16s %s\n", "cgroup(v2)", buf + 3);
	}
	fclose(f);
}

static void print_rlimit(const char *name, int res)
{
	struct rlimit rl;
	long rc = hss_prlimit(0, res, NULL, &rl);

	if (rc < 0) {
		printf("%-16s (error: %s)\n", name, strerror((int)-rc));
		return;
	}
	printf("%-16s ", name);
	if (rl.rlim_cur == RLIM_INFINITY) printf("soft=unlimited ");
	else printf("soft=%llu ", (unsigned long long)rl.rlim_cur);
	if (rl.rlim_max == RLIM_INFINITY) printf("hard=unlimited\n");
	else printf("hard=%llu\n", (unsigned long long)rl.rlim_max);
}

static const char *seccomp_name(long m)
{
	switch (m) {
	case HSS_SECCOMP_DISABLED: return "disabled";
	case HSS_SECCOMP_STRICT:   return "strict";
	case HSS_SECCOMP_FILTER:   return "filter";
	default:                   return "unknown";
	}
}

int main(int argc, char **argv)
{
	struct hss_state st;
	char why[160] = "";
	int require = (argc > 1 && !strcmp(argv[1], "--require"));
	int ok;

	if (argc > 1 && !require) {
		fputs("usage: hss-status [--require]\n", stderr);
		return 2;
	}
	if (hss_read_state(&st) != 0) {
		fputs("hss-status: cannot read /proc/self/status\n", stderr);
		return 1;
	}
	ok = hss_verify_confined(&st, why, sizeof why) == 0;

	printf("%-16s %ld\n", "pid", hss_raw_getpid());
	printf("%-16s %ld\n", "no_new_privs", st.no_new_privs);
	printf("%-16s %ld (%s)\n", "seccomp", st.seccomp_mode, seccomp_name(st.seccomp_mode));
	if (st.seccomp_filters >= 0)
		printf("%-16s %d\n", "seccomp_filters", st.seccomp_filters);
	printf("%-16s %ld\n", "dumpable", st.dumpable);
	printf("%-16s %016llx\n", "CapEff", st.cap_eff);
	printf("%-16s %016llx\n", "CapPrm", st.cap_prm);
	printf("%-16s %016llx\n", "CapInh", st.cap_inh);
	printf("%-16s %016llx\n", "CapAmb", st.cap_amb);
	printf("%-16s %016llx\n", "CapBnd", st.cap_bnd);
	print_file_line("apparmor", "/proc/self/attr/current");
	print_cgroup();
	print_rlimit("RLIMIT_NPROC", RLIMIT_NPROC);
	print_rlimit("RLIMIT_NOFILE", RLIMIT_NOFILE);
	print_rlimit("RLIMIT_FSIZE", RLIMIT_FSIZE);
	print_rlimit("RLIMIT_AS", RLIMIT_AS);
	print_rlimit("RLIMIT_CORE", RLIMIT_CORE);
	printf("%-16s %d\n", "open_fds", hss_count_open_fds());
	printf("%-16s %s%s%s\n", "confined", ok ? "yes" : "no",
	       ok ? "" : " - ", ok ? "" : why);

	return (require && !ok) ? 1 : 0;
}
