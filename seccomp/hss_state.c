/*
 * hss_state.c - read and check the confinement state of this process.
 *
 * sandbox-run calls hss_verify_confined() after loading the filter and
 * before exec. If any layer did not take effect it refuses to run the
 * command instead of running it unconfined (fail closed).
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hss.h"

static int parse_hex_field(const char *line, const char *key,
			   unsigned long long *out)
{
	size_t k = strlen(key);
	char *end;

	if (strncmp(line, key, k) != 0)
		return 0;
	line += k;
	while (*line == ' ' || *line == '\t')
		line++;
	errno = 0;
	*out = strtoull(line, &end, 16);
	return errno == 0 && end != line;
}

int hss_read_state(struct hss_state *st)
{
	FILE *f;
	char line[256];
	int seen = 0;

	memset(st, 0, sizeof *st);
	st->seccomp_filters = -1;
	st->no_new_privs = hss_get_no_new_privs();
	st->seccomp_mode = hss_get_seccomp_mode();
	st->dumpable = hss_get_dumpable();

	f = fopen("/proc/self/status", "re");
	if (!f)
		return -errno;
	while (fgets(line, sizeof line, f)) {
		seen += parse_hex_field(line, "CapInh:", &st->cap_inh);
		seen += parse_hex_field(line, "CapPrm:", &st->cap_prm);
		seen += parse_hex_field(line, "CapEff:", &st->cap_eff);
		seen += parse_hex_field(line, "CapBnd:", &st->cap_bnd);
		seen += parse_hex_field(line, "CapAmb:", &st->cap_amb);
		if (!strncmp(line, "Seccomp_filters:", 16))
			st->seccomp_filters = atoi(line + 16);
	}
	fclose(f);
	st->caps_known = (seen >= 4);
	return 0;
}

/*
 * 0 when every layer sandbox-run is responsible for is in place, else -1
 * with a short reason in why. The bounding set is not checked: an
 * unprivileged caller cannot drop it, and with all other sets empty and
 * no_new_privs set it grants nothing on exec.
 */
int hss_verify_confined(const struct hss_state *st, char *why, size_t whylen)
{
	if (st->no_new_privs != 1) {
		snprintf(why, whylen, "no_new_privs is %ld, want 1", st->no_new_privs);
		return -1;
	}
	if (st->seccomp_mode != HSS_SECCOMP_FILTER) {
		snprintf(why, whylen, "seccomp mode is %ld, want 2 (filter)",
			 st->seccomp_mode);
		return -1;
	}
	if (!st->caps_known) {
		snprintf(why, whylen, "could not read capabilities from /proc/self/status");
		return -1;
	}
	if (st->cap_eff || st->cap_prm || st->cap_inh || st->cap_amb) {
		snprintf(why, whylen,
			 "capabilities remain: eff=%llx prm=%llx inh=%llx amb=%llx",
			 st->cap_eff, st->cap_prm, st->cap_inh, st->cap_amb);
		return -1;
	}
	return 0;
}

/* Set soft = hard = value so the command cannot raise it. 0 or -errno. */
int hss_set_rlimit_both(int resource, rlim_t value)
{
	struct rlimit rl = { .rlim_cur = value, .rlim_max = value };
	long rc = hss_prlimit(0, resource, &rl, NULL);

	return rc < 0 ? (int)rc : 0;
}

/*
 * Parse "4096", "64K", "512M", "2G" (binary multiples). Rejects negatives,
 * trailing junk and overflow. 0 on success, -EINVAL otherwise.
 */
int hss_parse_size(const char *s, rlim_t *out)
{
	unsigned long long v, mul = 1;
	char *end;

	if (!s || !isdigit((unsigned char)*s))
		return -EINVAL;
	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno)
		return -EINVAL;
	switch (*end) {
	case '\0': break;
	case 'k': case 'K': mul = 1ULL << 10; end++; break;
	case 'm': case 'M': mul = 1ULL << 20; end++; break;
	case 'g': case 'G': mul = 1ULL << 30; end++; break;
	default: return -EINVAL;
	}
	if (*end != '\0')
		return -EINVAL;
	if (v > (unsigned long long)RLIM_INFINITY / mul)
		return -EINVAL;
	*out = (rlim_t)(v * mul);
	return 0;
}
