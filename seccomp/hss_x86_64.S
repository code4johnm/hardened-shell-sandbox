/*
 * x86-64 SysV helpers for sandbox-run.
 *
 * hss_drop_capabilities clears the process capability sets with the capset
 * syscall, then drops the bounding set with prctl. Raw stubs issue the
 * syscall instruction directly so tests observe the seccomp filter, not a
 * libc wrapper.
 *
 * Linux x86-64 syscall ABI: rax = number, rdi rsi rdx r10 r8 r9 = args,
 * result in rax as 0 or -errno. rcx and r11 are clobbered by syscall.
 *
 * Capability version 3 header is two 32-bit words (version, pid). The data
 * argument is two struct __user_cap_data (effective, permitted, inheritable),
 * 12 bytes each, covering the low and high 32 capability bits.
 */
	.text

	.globl	hss_drop_capabilities
	.type	hss_drop_capabilities, @function
hss_drop_capabilities:
	push	%rbp
	mov	%rsp, %rbp
	push	%r12
	push	%r13
	sub	$64, %rsp

	/* header: _LINUX_CAPABILITY_VERSION_3, pid 0 (current). */
	movl	$0x20080522, 0(%rsp)
	movl	$0, 4(%rsp)
	/* two zeroed capability words: effective = permitted = inheritable = 0. */
	xor	%rax, %rax
	mov	%rax, 16(%rsp)
	mov	%rax, 24(%rsp)
	mov	%rax, 32(%rsp)

	/* capset(header, data) = syscall 126. */
	mov	$126, %eax
	mov	%rsp, %rdi
	lea	16(%rsp), %rsi
	syscall
	test	%rax, %rax
	js	.Lfail

	/* prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0). */
	mov	$157, %eax
	mov	$47, %edi
	mov	$4, %esi
	xor	%edx, %edx
	xor	%r10, %r10
	xor	%r8, %r8
	syscall

	/* Remember euid (syscall 107). Bounding-set drops need CAP_SETPCAP. */
	mov	$107, %eax
	syscall
	mov	%rax, %r12

	xor	%r13d, %r13d
.Lcap:
	cmp	$64, %r13d
	jae	.Lok
	/* prctl(PR_CAPBSET_DROP, cap). EINVAL means the cap number is unused. */
	mov	$157, %eax
	mov	$24, %edi
	mov	%r13d, %esi
	xor	%edx, %edx
	xor	%r10, %r10
	xor	%r8, %r8
	syscall
	test	%rax, %rax
	jns	.Lnext
	cmp	$-1, %rax		/* EPERM: not privileged to drop the bound. */
	je	.Lnext
	cmp	$-22, %rax		/* EINVAL: no such capability. */
	je	.Lnext
	test	%r12, %r12		/* non-root: do not fail the launch. */
	jnz	.Lnext
	jmp	.Lfail
.Lnext:
	incl	%r13d
	jmp	.Lcap

.Lok:
	xor	%eax, %eax
	jmp	.Lout
.Lfail:
	test	%rax, %rax
	js	.Lout
	mov	$-1, %rax
.Lout:
	add	$64, %rsp
	pop	%r13
	pop	%r12
	pop	%rbp
	ret
	.size	hss_drop_capabilities, .-hss_drop_capabilities

/*
 * Each stub returns the raw syscall result (0 or -errno).
 * Arguments are the ones a probe needs to reach the filter. A successful
 * or differently-failed call without the filter is not a pass.
 */

	.globl	hss_raw_ptrace_traceme
	.type	hss_raw_ptrace_traceme, @function
hss_raw_ptrace_traceme:
	mov	$101, %eax		/* ptrace */
	xor	%edi, %edi		/* PTRACE_TRACEME */
	xor	%esi, %esi
	xor	%edx, %edx
	xor	%r10, %r10
	syscall
	ret
	.size	hss_raw_ptrace_traceme, .-hss_raw_ptrace_traceme

	.globl	hss_raw_unshare_newuser
	.type	hss_raw_unshare_newuser, @function
hss_raw_unshare_newuser:
	mov	$272, %eax		/* unshare */
	mov	$0x10000000, %edi	/* CLONE_NEWUSER */
	syscall
	ret
	.size	hss_raw_unshare_newuser, .-hss_raw_unshare_newuser

	.globl	hss_raw_mount
	.type	hss_raw_mount, @function
hss_raw_mount:
	mov	$165, %eax		/* mount */
	xor	%edi, %edi
	xor	%esi, %esi
	xor	%edx, %edx
	xor	%r10, %r10
	xor	%r8, %r8
	syscall
	ret
	.size	hss_raw_mount, .-hss_raw_mount

	.globl	hss_raw_umount2
	.type	hss_raw_umount2, @function
hss_raw_umount2:
	mov	$166, %eax		/* umount2 */
	xor	%edi, %edi
	xor	%esi, %esi
	syscall
	ret
	.size	hss_raw_umount2, .-hss_raw_umount2

	.globl	hss_raw_pivot_root
	.type	hss_raw_pivot_root, @function
hss_raw_pivot_root:
	mov	$155, %eax		/* pivot_root */
	xor	%edi, %edi
	xor	%esi, %esi
	syscall
	ret
	.size	hss_raw_pivot_root, .-hss_raw_pivot_root

	.globl	hss_raw_setns
	.type	hss_raw_setns, @function
hss_raw_setns:
	mov	$308, %eax		/* setns */
	mov	$-1, %edi
	xor	%esi, %esi
	syscall
	ret
	.size	hss_raw_setns, .-hss_raw_setns

	.globl	hss_raw_personality
	.type	hss_raw_personality, @function
hss_raw_personality:
	mov	$135, %eax		/* personality */
	mov	$0xffffffff, %edi	/* query current; filter still denies the call */
	syscall
	ret
	.size	hss_raw_personality, .-hss_raw_personality

	.globl	hss_raw_userfaultfd
	.type	hss_raw_userfaultfd, @function
hss_raw_userfaultfd:
	mov	$323, %eax		/* userfaultfd */
	xor	%edi, %edi
	syscall
	ret
	.size	hss_raw_userfaultfd, .-hss_raw_userfaultfd

	.globl	hss_raw_open_by_handle_at
	.type	hss_raw_open_by_handle_at, @function
hss_raw_open_by_handle_at:
	mov	$304, %eax		/* open_by_handle_at */
	mov	$-100, %edi		/* AT_FDCWD */
	xor	%esi, %esi
	xor	%edx, %edx
	syscall
	ret
	.size	hss_raw_open_by_handle_at, .-hss_raw_open_by_handle_at

	.globl	hss_raw_process_vm_writev
	.type	hss_raw_process_vm_writev, @function
hss_raw_process_vm_writev:
	mov	$311, %eax		/* process_vm_writev */
	xor	%edi, %edi
	xor	%esi, %esi
	xor	%edx, %edx
	xor	%r10, %r10
	xor	%r8, %r8
	xor	%r9, %r9
	syscall
	ret
	.size	hss_raw_process_vm_writev, .-hss_raw_process_vm_writev

	.globl	hss_raw_kexec_file_load
	.type	hss_raw_kexec_file_load, @function
hss_raw_kexec_file_load:
	mov	$320, %eax		/* kexec_file_load */
	xor	%edi, %edi
	xor	%esi, %esi
	xor	%edx, %edx
	xor	%r10, %r10
	xor	%r8, %r8
	syscall
	ret
	.size	hss_raw_kexec_file_load, .-hss_raw_kexec_file_load

	.globl	hss_raw_bpf
	.type	hss_raw_bpf, @function
hss_raw_bpf:
	mov	$321, %eax		/* bpf */
	xor	%edi, %edi
	xor	%esi, %esi
	xor	%edx, %edx
	syscall
	ret
	.size	hss_raw_bpf, .-hss_raw_bpf

	.globl	hss_raw_init_module
	.type	hss_raw_init_module, @function
hss_raw_init_module:
	mov	$175, %eax		/* init_module */
	xor	%edi, %edi
	xor	%esi, %esi
	xor	%edx, %edx
	syscall
	ret
	.size	hss_raw_init_module, .-hss_raw_init_module

	.globl	hss_raw_delete_module
	.type	hss_raw_delete_module, @function
hss_raw_delete_module:
	mov	$176, %eax		/* delete_module */
	xor	%edi, %edi
	xor	%esi, %esi
	syscall
	ret
	.size	hss_raw_delete_module, .-hss_raw_delete_module

	.globl	hss_raw_perf_event_open
	.type	hss_raw_perf_event_open, @function
hss_raw_perf_event_open:
	mov	$298, %eax		/* perf_event_open */
	xor	%edi, %edi
	xor	%esi, %esi
	xor	%edx, %edx
	xor	%r10, %r10
	xor	%r8d, %r8d
	syscall
	ret
	.size	hss_raw_perf_event_open, .-hss_raw_perf_event_open
