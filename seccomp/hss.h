/*
 * hss.h - shared declarations for the sandbox-run helpers.
 *
 * Raw helpers live in hss_x86_64.S and hss_state_x86_64.S. Each returns the
 * kernel result directly: >= 0 on success, -errno on failure. No errno is
 * set; callers decode the return value.
 *
 * The C helpers live in hss_fd.c and hss_state.c.
 */
#ifndef HSS_H
#define HSS_H

#include <stddef.h>
#include <sys/resource.h>
#include <sys/types.h>

/* hss_x86_64.S */
long hss_drop_capabilities(void);

/* hss_state_x86_64.S: process state and descriptor hygiene. */
long hss_set_no_new_privs(void);
long hss_get_no_new_privs(void);
long hss_get_seccomp_mode(void);
long hss_get_dumpable(void);
long hss_set_dumpable(long on);
long hss_close_range(unsigned int first, unsigned int last, unsigned int flags);
long hss_prlimit(pid_t pid, int resource, const struct rlimit *new_lim,
		 struct rlimit *old_lim);
long hss_raw_getpid(void);
long hss_raw_write(int fd, const void *buf, size_t len);
long hss_raw_syscall6(long nr, long a0, long a1, long a2, long a3, long a4,
		      long a5);

/* Values the kernel reports through PR_GET_SECCOMP. */
#define HSS_SECCOMP_DISABLED 0
#define HSS_SECCOMP_STRICT   1
#define HSS_SECCOMP_FILTER   2

/* hss_fd.c */
int hss_ensure_std_fds(void);
int hss_close_extra_fds(int keep_from);
int hss_count_open_fds(void);

/* hss_state.c */
struct hss_state {
	long no_new_privs;	/* 0 or 1, or -errno */
	long seccomp_mode;	/* HSS_SECCOMP_*, or -errno */
	long dumpable;		/* 0, 1, 2, or -errno */
	unsigned long long cap_eff;
	unsigned long long cap_prm;
	unsigned long long cap_inh;
	unsigned long long cap_bnd;
	unsigned long long cap_amb;
	int caps_known;		/* 1 when /proc/self/status was parsed */
	int seccomp_filters;	/* Seccomp_filters line, -1 if absent */
};

int hss_read_state(struct hss_state *st);
int hss_verify_confined(const struct hss_state *st, char *why, size_t whylen);
int hss_set_rlimit_both(int resource, rlim_t value);
int hss_parse_size(const char *s, rlim_t *out);

#endif /* HSS_H */
