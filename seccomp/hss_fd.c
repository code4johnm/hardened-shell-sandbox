/*
 * hss_fd.c - file descriptor hygiene before exec.
 *
 * A launcher inherits whatever descriptors its parent left open: sockets,
 * database handles, a terminal of another session. The confined command
 * should see stdin, stdout and stderr and nothing else unless the operator
 * asks for it (--keep-fds).
 *
 * close_range(2) does the job in one syscall on Linux 5.9+. Older kernels,
 * or a host filter that denies it, fall back to walking /proc/self/fd.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include "hss.h"

/*
 * If 0, 1 or 2 is closed, the first file the command opens would take that
 * number and could receive output meant for a terminal. Park /dev/null on
 * any missing standard descriptor. Returns 0 or -errno.
 */
int hss_ensure_std_fds(void)
{
	int fd;

	for (fd = 0; fd <= 2; fd++) {
		if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
			continue;
		int n = open("/dev/null", fd == 0 ? O_RDONLY : O_WRONLY);
		if (n < 0)
			return -errno;
		if (n != fd) {
			/* A lower slot was free; move it where it belongs. */
			if (dup2(n, fd) < 0) {
				int e = errno;
				close(n);
				return -e;
			}
			close(n);
		}
	}
	return 0;
}

static int close_extra_fds_proc(int keep_from)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *de;
	int self_fd, rc = 0;

	if (!d)
		return -errno;
	self_fd = dirfd(d);
	while ((de = readdir(d)) != NULL) {
		char *end;
		long v;

		if (de->d_name[0] < '0' || de->d_name[0] > '9')
			continue;
		errno = 0;
		v = strtol(de->d_name, &end, 10);
		if (errno || *end || v < keep_from || v > INT_MAX || v == self_fd)
			continue;
		/* close() may fail with EINTR yet still release the slot. */
		if (close((int)v) != 0 && errno != EINTR && errno != EBADF)
			rc = -errno;
	}
	closedir(d);
	return rc;
}

/*
 * Close every descriptor numbered keep_from and above. Returns 0 or -errno.
 * keep_from below 3 is raised to 3: the standard descriptors always stay.
 */
int hss_close_extra_fds(int keep_from)
{
	long rc;

	if (keep_from < 3)
		keep_from = 3;
	rc = hss_close_range((unsigned int)keep_from, ~0U, 0);
	if (rc == 0)
		return 0;
	if (rc != -ENOSYS && rc != -EPERM && rc != -EINVAL)
		return (int)rc;
	return close_extra_fds_proc(keep_from);
}

/* Number of open descriptors, or -errno. Used by tests and hss-status. */
int hss_count_open_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *de;
	int n = 0;

	if (!d)
		return -errno;
	while ((de = readdir(d)) != NULL)
		if (de->d_name[0] >= '0' && de->d_name[0] <= '9')
			n++;
	closedir(d);
	return n - 1;	/* the directory stream's own descriptor */
}
