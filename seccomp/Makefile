# Build the sandbox-run launcher.  Requires libseccomp-dev (libseccomp.so / seccomp.h).
CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDLIBS   ?= -lseccomp

sandbox-run: sandbox-run.c hss_x86_64.S
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ sandbox-run.c hss_x86_64.S $(LDFLAGS) $(LDLIBS)

../tests/escape_probe: ../tests/escape_probe.c hss_x86_64.S
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ ../tests/escape_probe.c hss_x86_64.S $(LDFLAGS)

clean:
	rm -f sandbox-run ../tests/escape_probe

.PHONY: clean
