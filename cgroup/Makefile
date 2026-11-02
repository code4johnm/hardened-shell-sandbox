# Build the hss-cgroup launcher. Plain libc; no extra libraries.
CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 -fstack-protector-strong

hss-cgroup: hss-cgroup.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f hss-cgroup

.PHONY: clean
