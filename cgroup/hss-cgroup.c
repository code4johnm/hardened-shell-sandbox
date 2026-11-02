/*
 * hss-cgroup - run a command inside a fresh cgroup v2 child with limits.
 *
 * DEFENSIVE TOOL ONLY. It bounds what the launched command can consume.
 *
 * Usage:
 *   hss-cgroup --parent DIR --name NAME [--pids-max N] [--memory-max SIZE]
 *              [--memory-swap-max SIZE] [--cpu-max QUOTA_US[/PERIOD_US]]
 *              [--exec] -- command [args...]
 *
 * DIR must be a cgroup v2 directory the caller may write to: a systemd
 * delegated subtree (systemd-run --user -p Delegate=yes ...), or a
 * directory an administrator created and chowned. The pids, memory and cpu
 * controllers must be listed in DIR/cgroup.subtree_control for the
 * matching option to work; hss-cgroup says which one is missing.
 *
 * Default (supervise): create DIR/NAME, write the limits, fork; the child
 * writes its own pid to cgroup.procs and execs the command; the parent
 * waits, returns the child's exit status, and removes DIR/NAME once it is
 * empty. With --exec, hss-cgroup moves itself in and execs, and NAME is
 * left behind for the caller to remove.
 *
 * Combine with sandbox-run for both layers:
 *   hss-cgroup --parent "$D" --name job1 --pids-max 64 --memory-max 512M \
 *       -- seccomp/sandbox-run --mode workdir-safe -- make test
 *
 * SIZE accepts bytes or a K, M or G suffix. pids.max is enforced per
 * cgroup (unlike RLIMIT_NPROC, which counts every task of the real UID).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

struct opts {
	const char *parent;
	const char *name;
	const char *pids_max;		/* validated strings, written as-is */
	char memory_max[32];
	char memory_swap_max[32];
	char cpu_max[48];
	int exec_mode;
};

static void usage(FILE *f)
{
	fputs("usage: hss-cgroup --parent DIR --name NAME [--pids-max N]\n"
	      "                  [--memory-max SIZE] [--memory-swap-max SIZE]\n"
	      "                  [--cpu-max QUOTA_US[/PERIOD_US]] [--exec]\n"
	      "                  -- command [args...]\n", f);
}

/* NAME: 1-64 of [A-Za-z0-9._-], not starting with '.', so it can never be
 * "..", a hidden name, or contain a slash. */
static int valid_name(const char *s)
{
	size_t n = strlen(s), i;

	if (n == 0 || n > 64 || s[0] == '.')
		return 0;
	for (i = 0; i < n; i++) {
		char c = s[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
			return 0;
	}
	return 1;
}

static int parse_u64(const char *s, unsigned long long *out)
{
	char *end;

	if (!s || *s < '0' || *s > '9')
		return -1;
	errno = 0;
	*out = strtoull(s, &end, 10);
	return (errno || *end) ? -1 : 0;
}

/* SIZE -> decimal byte string in buf. */
static int parse_size(const char *s, char *buf, size_t len)
{
	unsigned long long v, mul = 1;
	char *end;

	if (!s || *s < '0' || *s > '9')
		return -1;
	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno)
		return -1;
	switch (*end) {
	case '\0': break;
	case 'k': case 'K': mul = 1ULL << 10; end++; break;
	case 'm': case 'M': mul = 1ULL << 20; end++; break;
	case 'g': case 'G': mul = 1ULL << 30; end++; break;
	default: return -1;
	}
	if (*end || v > ULLONG_MAX / mul)
		return -1;
	snprintf(buf, len, "%llu", v * mul);
	return 0;
}

/* "50000" or "50000/100000" -> "50000 100000". Quota 1000us..period*1024. */
static int parse_cpu(const char *s, char *buf, size_t len)
{
	char tmp[48], *slash;
	unsigned long long q, p = 100000;

	if (strlen(s) >= sizeof tmp)
		return -1;
	strcpy(tmp, s);
	slash = strchr(tmp, '/');
	if (slash) {
		*slash = '\0';
		if (parse_u64(slash + 1, &p) || p < 1000 || p > 1000000)
			return -1;
	}
	if (parse_u64(tmp, &q) || q < 1000 || q > p * 1024)
		return -1;
	snprintf(buf, len, "%llu %llu", q, p);
	return 0;
}

static int write_at(int dfd, const char *file, const char *val)
{
	int fd = openat(dfd, file, O_WRONLY | O_CLOEXEC);
	size_t n = strlen(val);
	ssize_t w;

	if (fd < 0)
		return -errno;
	w = write(fd, val, n);
	if (w < 0 || (size_t)w != n) {
		int e = w < 0 ? errno : EIO;
		close(fd);
		return -e;
	}
	return close(fd) == 0 ? 0 : -errno;
}

static int set_limit(int cg, const char *file, const char *val,
		     const char *controller)
{
	int rc = write_at(cg, file, val);

	if (rc == -ENOENT) {
		fprintf(stderr, "hss-cgroup: %s missing: enable the %s controller "
			"in the parent's cgroup.subtree_control\n", file, controller);
		return -1;
	}
	if (rc) {
		fprintf(stderr, "hss-cgroup: write %s=%s: %s\n", file, val, strerror(-rc));
		return -1;
	}
	return 0;
}

static int apply_limits(int cg, const struct opts *o)
{
	if (o->pids_max && set_limit(cg, "pids.max", o->pids_max, "pids"))
		return -1;
	if (o->memory_max[0] && set_limit(cg, "memory.max", o->memory_max, "memory"))
		return -1;
	if (o->memory_swap_max[0] &&
	    set_limit(cg, "memory.swap.max", o->memory_swap_max, "memory"))
		return -1;
	if (o->cpu_max[0] && set_limit(cg, "cpu.max", o->cpu_max, "cpu"))
		return -1;
	return 0;
}

/* Move pid ("0" = the caller) into the cgroup. */
static int join(int cg)
{
	int rc = write_at(cg, "cgroup.procs", "0");

	if (rc) {
		fprintf(stderr, "hss-cgroup: join cgroup.procs: %s\n", strerror(-rc));
		return -1;
	}
	return 0;
}

static void remove_cgroup(int pfd, const char *name)
{
	int tries;

	/* A just-exited task can linger briefly; retry for up to ~1 second. */
	for (tries = 0; tries < 20; tries++) {
		if (unlinkat(pfd, name, AT_REMOVEDIR) == 0 || errno == ENOENT)
			return;
		if (errno != EBUSY)
			break;
		usleep(50000);
	}
	fprintf(stderr, "hss-cgroup: note: could not remove cgroup %s: %s\n",
		name, strerror(errno));
}

int main(int argc, char **argv)
{
	struct opts o;
	struct statfs sfs;
	int i, pfd, cg, status;
	pid_t child;

	memset(&o, 0, sizeof o);
	for (i = 1; i < argc; i++) {
		const char *a = argv[i];
		const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;

		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); return 0; }
		if (!strcmp(a, "--exec")) { o.exec_mode = 1; continue; }
		if (!v) { usage(stderr); return 2; }
		if (!strcmp(a, "--parent")) o.parent = v;
		else if (!strcmp(a, "--name")) o.name = v;
		else if (!strcmp(a, "--pids-max")) {
			unsigned long long n;
			if (parse_u64(v, &n) || n < 1 || n > 4194304) {
				fputs("hss-cgroup: --pids-max must be 1..4194304\n", stderr);
				return 2;
			}
			o.pids_max = v;
		}
		else if (!strcmp(a, "--memory-max")) {
			if (parse_size(v, o.memory_max, sizeof o.memory_max)) {
				fputs("hss-cgroup: bad --memory-max\n", stderr);
				return 2;
			}
		}
		else if (!strcmp(a, "--memory-swap-max")) {
			if (parse_size(v, o.memory_swap_max, sizeof o.memory_swap_max)) {
				fputs("hss-cgroup: bad --memory-swap-max\n", stderr);
				return 2;
			}
		}
		else if (!strcmp(a, "--cpu-max")) {
			if (parse_cpu(v, o.cpu_max, sizeof o.cpu_max)) {
				fputs("hss-cgroup: bad --cpu-max (QUOTA_US[/PERIOD_US])\n", stderr);
				return 2;
			}
		}
		else { usage(stderr); return 2; }
		i++;
	}
	if (!o.parent || !o.name || i >= argc) { usage(stderr); return 2; }
	if (!valid_name(o.name)) {
		fputs("hss-cgroup: --name must be 1-64 of [A-Za-z0-9._-], not starting with '.'\n",
		      stderr);
		return 2;
	}

	pfd = open(o.parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (pfd < 0) {
		fprintf(stderr, "hss-cgroup: open %s: %s\n", o.parent, strerror(errno));
		return 1;
	}
	if (fstatfs(pfd, &sfs) != 0 || (unsigned long)sfs.f_type != CGROUP2_SUPER_MAGIC) {
		fprintf(stderr, "hss-cgroup: %s is not on a cgroup v2 filesystem\n", o.parent);
		return 1;
	}
	if (mkdirat(pfd, o.name, 0755) != 0) {
		fprintf(stderr, "hss-cgroup: create %s/%s: %s\n", o.parent, o.name,
			strerror(errno));
		return 1;
	}
	cg = openat(pfd, o.name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cg < 0 || apply_limits(cg, &o) != 0) {
		if (cg < 0)
			fprintf(stderr, "hss-cgroup: open new cgroup: %s\n", strerror(errno));
		remove_cgroup(pfd, o.name);
		return 1;
	}

	if (o.exec_mode) {
		if (join(cg) != 0) { remove_cgroup(pfd, o.name); return 1; }
		execvp(argv[i], &argv[i]);
		fprintf(stderr, "hss-cgroup: exec %s: %s\n", argv[i], strerror(errno));
		return 127;
	}

	child = fork();
	if (child < 0) {
		perror("hss-cgroup: fork");
		remove_cgroup(pfd, o.name);
		return 1;
	}
	if (child == 0) {
		if (join(cg) != 0)
			_exit(126);
		execvp(argv[i], &argv[i]);
		fprintf(stderr, "hss-cgroup: exec %s: %s\n", argv[i], strerror(errno));
		_exit(127);
	}

	/* Supervisor: ignore terminal signals the child also receives so we
	 * live long enough to clean up, then mirror the child's status. */
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	while (waitpid(child, &status, 0) < 0) {
		if (errno != EINTR) {
			perror("hss-cgroup: waitpid");
			return 1;
		}
	}
	close(cg);
	remove_cgroup(pfd, o.name);
	close(pfd);

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	return 1;
}
