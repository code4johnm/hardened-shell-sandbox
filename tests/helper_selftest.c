/*
 * helper_selftest - unit tests for the sandbox-run helpers.
 *
 * Benign: it only reads its own process state, uses pipes and /dev/null,
 * and changes limits in forked children that exit immediately.
 *
 *   helper_selftest              test the assembly and C helpers
 *   helper_selftest --confined   also require that this process is fully
 *                                confined and holds only fds 0-2 (run it
 *                                under sandbox-run)
 *
 * Prints PASS/FAIL lines and exits non-zero on any failure.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../seccomp/hss.h"

static int passed, failed;

#define CHECK(name, cond)                                                     \
	do {                                                                  \
		if (cond) { printf("PASS  %s\n", name); passed++; }           \
		else { printf("FAIL  %s (line %d)\n", name, __LINE__); failed++; } \
	} while (0)

/* Run fn in a child; the child's exit code 0 means pass. */
static int in_child(int (*fn)(void))
{
	int st;
	pid_t p;

	fflush(stdout);
	p = fork();
	if (p < 0)
		return 0;
	if (p == 0)
		_exit(fn() ? 0 : 1);
	if (waitpid(p, &st, 0) < 0)
		return 0;
	return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static int child_nnp(void)
{
	if (hss_set_no_new_privs() != 0)
		return 0;
	return hss_get_no_new_privs() == 1;
}

static int child_dumpable(void)
{
	if (hss_set_dumpable(0) != 0 || hss_get_dumpable() != 0)
		return 0;
	if (hss_set_dumpable(7) != 0)	/* normalised to 1 */
		return 0;
	return hss_get_dumpable() == 1;
}

static int child_prlimit(void)
{
	struct rlimit cur, now;

	if (hss_prlimit(0, RLIMIT_NOFILE, NULL, &cur) != 0 || cur.rlim_cur < 32)
		return 0;
	if (hss_set_rlimit_both(RLIMIT_NOFILE, 32) != 0)
		return 0;
	if (getrlimit(RLIMIT_NOFILE, &now) != 0)
		return 0;
	if (now.rlim_cur != 32 || now.rlim_max != 32)
		return 0;
	/* Raising the hard limit back must now fail without privilege. */
	return hss_set_rlimit_both(RLIMIT_NOFILE, 64) == -EPERM || geteuid() == 0;
}

static int child_close_extra(void)
{
	int i;

	for (i = 0; i < 6; i++)
		if (open("/dev/null", O_RDONLY) < 0)
			return 0;
	if (dup2(0, 200) != 200)
		return 0;
	if (hss_close_extra_fds(3) != 0)
		return 0;
	if (fcntl(200, F_GETFD) != -1 || errno != EBADF)
		return 0;
	return hss_count_open_fds() == 3;
}

static int child_std_fds(void)
{
	close(0);
	if (fcntl(0, F_GETFD) != -1)
		return 0;
	if (hss_ensure_std_fds() != 0)
		return 0;
	return fcntl(0, F_GETFD) != -1 && (fcntl(0, F_GETFL) & O_ACCMODE) == O_RDONLY;
}

static void test_raw(void)
{
	int p[2], fd;
	char out[9000], in[9000];
	size_t got = 0;
	ssize_t r;
	long rc;

	CHECK("raw getpid matches libc", hss_raw_getpid() == (long)getpid());
	CHECK("raw_syscall6 getppid matches libc",
	      hss_raw_syscall6(SYS_getppid, 0, 0, 0, 0, 0, 0) == (long)getppid());
	CHECK("raw_syscall6 returns -errno",
	      hss_raw_syscall6(SYS_close, -1, 0, 0, 0, 0, 0) == -EBADF);

	memset(out, 'h', sizeof out);
	out[sizeof out - 1] = 'z';
	if (pipe(p) == 0) {
		rc = hss_raw_write(p[1], out, sizeof out);
		CHECK("raw write: full length written", rc == (long)sizeof out);
		close(p[1]);
		while ((r = read(p[0], in + got, sizeof in - got)) > 0)
			got += (size_t)r;
		close(p[0]);
		CHECK("raw write: bytes intact", got == sizeof out && !memcmp(in, out, got));
	} else {
		CHECK("pipe()", 0);
	}
	CHECK("raw write: bad fd -> -EBADF", hss_raw_write(-1, "x", 1) == -EBADF);
	CHECK("raw write: zero length -> 0", hss_raw_write(1, "", 0) == 0);

	fd = dup(1);
	if (fd >= 0) {
		int hi = dup2(fd, 150);
		rc = hss_close_range(150, 150, 0);
		if (rc == -ENOSYS) {
			printf("SKIP  close_range not available on this kernel\n");
			close(150);
		} else {
			CHECK("close_range closes the range",
			      rc == 0 && hi == 150 && fcntl(150, F_GETFD) == -1);
		}
		CHECK("close_range leaves other fds", fcntl(fd, F_GETFD) != -1);
		close(fd);
	}

	rc = hss_get_seccomp_mode();
	CHECK("PR_GET_SECCOMP returns 0 or 2", rc == 0 || rc == 2);
	rc = hss_get_no_new_privs();
	CHECK("PR_GET_NO_NEW_PRIVS returns 0 or 1", rc == 0 || rc == 1);
	CHECK("no_new_privs set + read back (child)", in_child(child_nnp));
	CHECK("dumpable toggles and normalises (child)", in_child(child_dumpable));
	CHECK("prlimit sets soft=hard (child)", in_child(child_prlimit));
	CHECK("close_extra_fds leaves 0-2 only (child)", in_child(child_close_extra));
	CHECK("ensure_std_fds refills fd 0 (child)", in_child(child_std_fds));
}

static void test_parse(void)
{
	rlim_t v;

	CHECK("parse 4096", hss_parse_size("4096", &v) == 0 && v == 4096);
	CHECK("parse 64K", hss_parse_size("64K", &v) == 0 && v == 65536);
	CHECK("parse 512m", hss_parse_size("512m", &v) == 0 && v == (rlim_t)512 << 20);
	CHECK("parse 2G", hss_parse_size("2G", &v) == 0 && v == (rlim_t)2 << 30);
	CHECK("reject empty", hss_parse_size("", &v) != 0);
	CHECK("reject negative", hss_parse_size("-1", &v) != 0);
	CHECK("reject junk suffix", hss_parse_size("10KB", &v) != 0);
	CHECK("reject unknown unit", hss_parse_size("10T", &v) != 0);
	CHECK("reject overflow", hss_parse_size("99999999999999999999G", &v) != 0);
}

static void test_verify(void)
{
	struct hss_state st;
	char why[160];

	memset(&st, 0, sizeof st);
	st.no_new_privs = 1;
	st.seccomp_mode = HSS_SECCOMP_FILTER;
	st.caps_known = 1;
	st.cap_bnd = ~0ULL;	/* bounding set alone is acceptable */
	CHECK("verify: confined state accepted", hss_verify_confined(&st, why, sizeof why) == 0);

	st.no_new_privs = 0;
	CHECK("verify: missing no_new_privs rejected",
	      hss_verify_confined(&st, why, sizeof why) != 0 && strstr(why, "no_new_privs"));
	st.no_new_privs = 1;
	st.seccomp_mode = HSS_SECCOMP_DISABLED;
	CHECK("verify: no filter rejected",
	      hss_verify_confined(&st, why, sizeof why) != 0 && strstr(why, "seccomp"));
	st.seccomp_mode = HSS_SECCOMP_FILTER;
	st.cap_eff = 1ULL << 21;	/* CAP_SYS_ADMIN */
	CHECK("verify: leftover capability rejected",
	      hss_verify_confined(&st, why, sizeof why) != 0 && strstr(why, "capabilities"));
	st.cap_eff = 0;
	st.cap_amb = 1;
	CHECK("verify: ambient capability rejected",
	      hss_verify_confined(&st, why, sizeof why) != 0);
	st.cap_amb = 0;
	st.caps_known = 0;
	CHECK("verify: unknown caps rejected", hss_verify_confined(&st, why, sizeof why) != 0);
}

static void test_confined(void)
{
	struct hss_state st;
	char why[160] = "";

	CHECK("read own state", hss_read_state(&st) == 0);
	CHECK("running confined", hss_verify_confined(&st, why, sizeof why) == 0);
	if (why[0])
		printf("INFO  %s\n", why);
	CHECK("only fds 0-2 inherited", hss_count_open_fds() == 3);
	CHECK("seccomp filter count >= 1", st.seccomp_filters != 0);
	CHECK("raw ptrace still denied",
	      hss_raw_syscall6(SYS_ptrace, 0, 0, 0, 0, 0, 0) == -EPERM);
}

int main(int argc, char **argv)
{
	int confined = (argc > 1 && !strcmp(argv[1], "--confined"));

	if (argc > 1 && !confined) {
		fputs("usage: helper_selftest [--confined]\n", stderr);
		return 2;
	}
	if (confined) {
		/* Spawning is denied in strict mode, so skip the fork-based tests. */
		test_confined();
	} else {
		test_raw();
		test_parse();
		test_verify();
	}
	printf("\npassed=%d failed=%d\n", passed, failed);
	return failed ? 1 : 0;
}
