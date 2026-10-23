# Build the sandbox-run launcher.  Requires libseccomp-dev (libseccomp.so / seccomp.h).
CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDLIBS   ?= -lseccomp

sandbox-run: sandbox-run.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f sandbox-run

.PHONY: clean
