/*
 * Print raw syscall results from seccomp/hss_x86_64.S.
 * Under sandbox-run each of these must come back as errno 1 (EPERM).
 */
#include <stdio.h>

extern long hss_raw_ptrace_traceme(void);
extern long hss_raw_unshare_newuser(void);
extern long hss_raw_mount(void);
extern long hss_raw_umount2(void);
extern long hss_raw_pivot_root(void);
extern long hss_raw_setns(void);
extern long hss_raw_personality(void);
extern long hss_raw_userfaultfd(void);
extern long hss_raw_open_by_handle_at(void);
extern long hss_raw_process_vm_writev(void);
extern long hss_raw_kexec_file_load(void);
extern long hss_raw_bpf(void);
extern long hss_raw_init_module(void);
extern long hss_raw_delete_module(void);
extern long hss_raw_perf_event_open(void);

static void show(const char *name, long rc)
{
	if (rc < 0)
		printf("%s: FAILED errno=%ld\n", name, -rc);
	else
		printf("%s: OK raw=%ld\n", name, rc);
}

int main(void)
{
	show("ptrace", hss_raw_ptrace_traceme());
	show("unshare", hss_raw_unshare_newuser());
	show("mount", hss_raw_mount());
	show("umount2", hss_raw_umount2());
	show("pivot_root", hss_raw_pivot_root());
	show("setns", hss_raw_setns());
	show("personality", hss_raw_personality());
	show("userfaultfd", hss_raw_userfaultfd());
	show("open_by_handle_at", hss_raw_open_by_handle_at());
	show("process_vm_writev", hss_raw_process_vm_writev());
	show("kexec_file_load", hss_raw_kexec_file_load());
	show("bpf", hss_raw_bpf());
	show("init_module", hss_raw_init_module());
	show("delete_module", hss_raw_delete_module());
	show("perf_event_open", hss_raw_perf_event_open());
	return 0;
}
