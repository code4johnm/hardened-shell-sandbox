/*
 * sandbox-run - run a command under a seccomp-bpf filter and resource limits.
 *
 * DEFENSIVE TOOL ONLY.  It restricts what the launched command may do.
 *
 * Build:  make            (needs libseccomp-dev)
 * Usage:  sandbox-run [--mode strict|workdir-safe] [--nproc N] [--no-spawn]
 *                     [--workdir DIR] [--log] [--quiet] -- command [args...]
 *
 * Order of operations: set no_new_privs, set RLIMIT_NPROC (soft=hard) and
 * RLIMIT_CORE=0, optionally chdir, build + load the seccomp filter, execvp().
 *
 * Honest limits (see README.md):
 *   - seccomp is STATELESS.  It cannot count processes.  The process cap comes
 *     from RLIMIT_NPROC here (per real UID!) and from cgroup pids.max /
 *     systemd TasksMax.  The filter itself can only forbid process creation
 *     outright (--no-spawn, and mode "strict").
 *   - seccomp cannot dereference pointer arguments, so it cannot know WHICH
 *     path an unlink touches.  Path confinement is AppArmor's / mount
 *     namespaces' job.
 *   - Default action is ALLOW; this is a deny-list, not an allow-list.
 *
 * Modes
 *   strict         EPERM on unlink, unlinkat, rmdir, rename, renameat,
 *                  renameat2 (rename can overwrite/destroy) and on creation of
 *                  new processes (fork, vfork, clone without CLONE_THREAD;
 *                  clone3 -> ENOSYS so libc falls back to clone).
 *   workdir-safe   chdir()s into --workdir (default $HOME/sandbox-work),
 *                  allows deleting regular files but forbids removing
 *                  directories (rmdir, unlinkat with AT_REMOVEDIR), so a
 *                  directory tree can never be removed.  Spawning allowed
 *                  (bounded by RLIMIT_NPROC); add --no-spawn to forbid it.
 *
 * Errors: a blocked call fails with EPERM ("Operation not permitted") and the
 * program continues; it is NOT killed.  --log replaces the block with
 * SCMP_ACT_LOG (allow + audit record) so you can observe before enforcing.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif

enum mode { MODE_STRICT, MODE_WORKDIR };

static void usage(FILE *f)
{
	fputs("usage: sandbox-run [--mode strict|workdir-safe] [--nproc N] [--no-spawn]\n"
	      "                   [--workdir DIR] [--log] [--quiet] -- command [args...]\n", f);
}

static int die_seccomp(const char *what, int rc)
{
	fprintf(stderr, "sandbox-run: seccomp %s failed: %s\n", what, strerror(-rc));
	return 1;
}

/* Add a rule; "deny" is EPERM, or LOG when --log. */
#define ADD(ctx, act, sc, ...)                                                \
	do {                                                                  \
		int r_ = seccomp_rule_add((ctx), (act), (sc), __VA_ARGS__);   \
		if (r_ < 0) {                                                 \
			/* Syscall absent on this arch (e.g. unlink on arm64). */\
			if (r_ != -EDOM && r_ != -EFAULT)                     \
				return die_seccomp(#sc, r_);                  \
		}                                                             \
	} while (0)

int main(int argc, char **argv)
{
	enum mode mode = MODE_STRICT;
	long nproc = 256;
	int no_spawn = 0, logonly = 0, quiet = 0;
	const char *workdir = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--")) { i++; break; }
		else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
			i++;
			if (!strcmp(argv[i], "strict")) mode = MODE_STRICT;
			else if (!strcmp(argv[i], "workdir-safe")) mode = MODE_WORKDIR;
			else { usage(stderr); return 2; }
		}
		else if (!strcmp(argv[i], "--nproc") && i + 1 < argc) nproc = atol(argv[++i]);
		else if (!strcmp(argv[i], "--workdir") && i + 1 < argc) workdir = argv[++i];
		else if (!strcmp(argv[i], "--no-spawn")) no_spawn = 1;
		else if (!strcmp(argv[i], "--log")) logonly = 1;
		else if (!strcmp(argv[i], "--quiet")) quiet = 1;
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(stdout); return 0; }
		else break;
	}
	if (i >= argc || nproc < 1) { usage(stderr); return 2; }
	if (mode == MODE_STRICT) no_spawn = 1;

	/* 1. no_new_privs: the filter cannot be shed via setuid/file caps. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("sandbox-run: PR_SET_NO_NEW_PRIVS");
		return 1;
	}

	/* 2. Resource limits (soft = hard so the child cannot raise them). */
	struct rlimit rl = { .rlim_cur = (rlim_t)nproc, .rlim_max = (rlim_t)nproc };
	if (setrlimit(RLIMIT_NPROC, &rl) != 0) { perror("sandbox-run: RLIMIT_NPROC"); return 1; }
	struct rlimit core0 = { 0, 0 };
	(void)setrlimit(RLIMIT_CORE, &core0);

	/* 3. Working directory for workdir-safe. */
	if (mode == MODE_WORKDIR) {
		if (!workdir) {
			static char buf[4096];
			const char *home = getenv("HOME");
			if (!home) { fputs("sandbox-run: HOME unset; use --workdir\n", stderr); return 1; }
			snprintf(buf, sizeof buf, "%s/sandbox-work", home);
			workdir = buf;
		}
		if (chdir(workdir) != 0) { perror("sandbox-run: chdir workdir"); return 1; }
	}

	/* 4. Build the filter: default ALLOW, deny-list below. */
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (!ctx) { fputs("sandbox-run: seccomp_init failed\n", stderr); return 1; }
	const uint32_t deny = logonly ? SCMP_ACT_LOG : SCMP_ACT_ERRNO(EPERM);

	if (mode == MODE_STRICT) {
		ADD(ctx, deny, SCMP_SYS(unlink), 0);
		ADD(ctx, deny, SCMP_SYS(unlinkat), 0);
		ADD(ctx, deny, SCMP_SYS(rmdir), 0);
		ADD(ctx, deny, SCMP_SYS(rename), 0);
		ADD(ctx, deny, SCMP_SYS(renameat), 0);
		ADD(ctx, deny, SCMP_SYS(renameat2), 0);
	} else {
		/* Files may be removed; directories may not. */
		ADD(ctx, deny, SCMP_SYS(rmdir), 0);
		ADD(ctx, deny, SCMP_SYS(unlinkat), 1,
		    SCMP_A2(SCMP_CMP_MASKED_EQ, AT_REMOVEDIR, AT_REMOVEDIR));
	}

	if (no_spawn) {
		/* New processes only. Threads (CLONE_THREAD) keep working. */
		ADD(ctx, deny, SCMP_SYS(fork), 0);
		ADD(ctx, deny, SCMP_SYS(vfork), 0);
		ADD(ctx, deny, SCMP_SYS(clone), 1,
		    SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_THREAD, 0));
		/* clone3 flags live in a struct (not inspectable): report ENOSYS so
		 * glibc falls back to clone(), which we can filter. With --log we
		 * leave clone3 alone. */
		if (!logonly)
			ADD(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0);
	}

	int rc = seccomp_load(ctx);
	if (rc < 0) { seccomp_release(ctx); return die_seccomp("load", rc); }
	seccomp_release(ctx);

	if (!quiet)
		fprintf(stderr, "sandbox-run: mode=%s nproc<=%ld no-spawn=%d action=%s\n",
			mode == MODE_STRICT ? "strict" : "workdir-safe", nproc, no_spawn,
			logonly ? "LOG (not enforcing)" : "ERRNO(EPERM)");

	execvp(argv[i], &argv[i]);
	fprintf(stderr, "sandbox-run: exec %s: %s\n", argv[i], strerror(errno));
	return 127;
}
