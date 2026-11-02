/*
 * x86-64 SysV raw syscall helpers for process state and descriptor hygiene.
 *
 * Every helper returns the kernel result unchanged in rax: >= 0 on success,
 * -errno on failure. They never touch errno, which keeps them usable after
 * the seccomp filter is loaded and from signal handlers.
 *
 * Linux x86-64 syscall ABI: rax = number, rdi rsi rdx r10 r8 r9 = args.
 * The C ABI passes the 4th argument in rcx, so helpers that take four or
 * more arguments move rcx into r10 before the syscall instruction. The
 * syscall instruction clobbers rcx and r11; both are caller-saved, so no
 * spills are needed.
 *
 * Syscall numbers used (arch/x86/entry/syscalls/syscall_64.tbl):
 *   1 write   39 getpid   157 prctl   302 prlimit64   436 close_range
 *
 * prctl options used (include/uapi/linux/prctl.h):
 *   3 PR_GET_DUMPABLE   4 PR_SET_DUMPABLE   21 PR_GET_SECCOMP
 *   38 PR_SET_NO_NEW_PRIVS   39 PR_GET_NO_NEW_PRIVS
 */
	.text

/* long hss_set_no_new_privs(void): prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) */
	.globl	hss_set_no_new_privs
	.type	hss_set_no_new_privs, @function
hss_set_no_new_privs:
	mov	$157, %eax
	mov	$38, %edi
	mov	$1, %esi
	xor	%edx, %edx
	xor	%r10d, %r10d
	xor	%r8d, %r8d
	syscall
	ret
	.size	hss_set_no_new_privs, .-hss_set_no_new_privs

/* long hss_get_no_new_privs(void): 0 or 1 */
	.globl	hss_get_no_new_privs
	.type	hss_get_no_new_privs, @function
hss_get_no_new_privs:
	mov	$157, %eax
	mov	$39, %edi
	xor	%esi, %esi
	xor	%edx, %edx
	xor	%r10d, %r10d
	xor	%r8d, %r8d
	syscall
	ret
	.size	hss_get_no_new_privs, .-hss_get_no_new_privs

/*
 * long hss_get_seccomp_mode(void): 0 disabled, 2 filter.
 * In SECCOMP_MODE_STRICT the call itself is fatal, which is the kernel's
 * documented behaviour; sandbox-run never enters strict mode 1.
 */
	.globl	hss_get_seccomp_mode
	.type	hss_get_seccomp_mode, @function
hss_get_seccomp_mode:
	mov	$157, %eax
	mov	$21, %edi
	xor	%esi, %esi
	xor	%edx, %edx
	xor	%r10d, %r10d
	xor	%r8d, %r8d
	syscall
	ret
	.size	hss_get_seccomp_mode, .-hss_get_seccomp_mode

/* long hss_get_dumpable(void): 0, 1 or 2 */
	.globl	hss_get_dumpable
	.type	hss_get_dumpable, @function
hss_get_dumpable:
	mov	$157, %eax
	mov	$3, %edi
	xor	%esi, %esi
	xor	%edx, %edx
	xor	%r10d, %r10d
	xor	%r8d, %r8d
	syscall
	ret
	.size	hss_get_dumpable, .-hss_get_dumpable

/* long hss_set_dumpable(long on): on is normalised to 0 or 1 */
	.globl	hss_set_dumpable
	.type	hss_set_dumpable, @function
hss_set_dumpable:
	xor	%esi, %esi
	test	%rdi, %rdi
	setnz	%sil
	mov	$157, %eax
	mov	$4, %edi
	xor	%edx, %edx
	xor	%r10d, %r10d
	xor	%r8d, %r8d
	syscall
	ret
	.size	hss_set_dumpable, .-hss_set_dumpable

/*
 * long hss_close_range(unsigned first, unsigned last, unsigned flags)
 * Arguments are already in rdi, rsi, rdx. Returns -ENOSYS on kernels
 * older than 5.9, so callers keep a /proc/self/fd fallback.
 */
	.globl	hss_close_range
	.type	hss_close_range, @function
hss_close_range:
	mov	$436, %eax
	mov	%edi, %edi		/* zero-extend the unsigned ints */
	mov	%esi, %esi
	mov	%edx, %edx
	syscall
	ret
	.size	hss_close_range, .-hss_close_range

/*
 * long hss_prlimit(pid_t pid, int resource, const struct rlimit *new,
 *                  struct rlimit *old)
 * C passes the 4th argument in rcx; the kernel wants it in r10.
 */
	.globl	hss_prlimit
	.type	hss_prlimit, @function
hss_prlimit:
	mov	%rcx, %r10
	movslq	%edi, %rdi
	mov	%esi, %esi
	mov	$302, %eax
	syscall
	ret
	.size	hss_prlimit, .-hss_prlimit

/* long hss_raw_getpid(void) */
	.globl	hss_raw_getpid
	.type	hss_raw_getpid, @function
hss_raw_getpid:
	mov	$39, %eax
	syscall
	ret
	.size	hss_raw_getpid, .-hss_raw_getpid

/*
 * long hss_raw_write(int fd, const void *buf, size_t len)
 * Retries on -EINTR and on short writes until len bytes are written or an
 * error is returned. Returns the byte count written or -errno.
 */
	.globl	hss_raw_write
	.type	hss_raw_write, @function
hss_raw_write:
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	sub	$8, %rsp		/* keep rsp 16-byte aligned */
	mov	%edi, %ebx		/* fd */
	mov	%rsi, %r12		/* cursor */
	mov	%rdx, %r13		/* remaining */
	xor	%r14d, %r14d		/* total written */
.Lw_loop:
	test	%r13, %r13
	jz	.Lw_done
	mov	$1, %eax
	mov	%ebx, %edi
	mov	%r12, %rsi
	mov	%r13, %rdx
	syscall
	cmp	$-4, %rax		/* -EINTR: try again */
	je	.Lw_loop
	test	%rax, %rax
	js	.Lw_err
	jz	.Lw_done		/* no progress: stop, report short */
	add	%rax, %r12
	sub	%rax, %r13
	add	%rax, %r14
	jmp	.Lw_loop
.Lw_err:
	test	%r14, %r14		/* partial success wins over the error */
	jnz	.Lw_done
	jmp	.Lw_out
.Lw_done:
	mov	%r14, %rax
.Lw_out:
	add	$8, %rsp
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx
	ret
	.size	hss_raw_write, .-hss_raw_write

/*
 * long hss_raw_syscall6(long nr, long a0, long a1, long a2, long a3,
 *                       long a4, long a5)
 * Generic stub used by the self-tests to reach the filter directly.
 * C: rdi=nr rsi=a0 rdx=a1 rcx=a2 r8=a3 r9=a4 8(%rsp)=a5.
 * Kernel: rax=nr rdi=a0 rsi=a1 rdx=a2 r10=a3 r8=a4 r9=a5.
 */
	.globl	hss_raw_syscall6
	.type	hss_raw_syscall6, @function
hss_raw_syscall6:
	mov	%rdi, %rax
	mov	%rsi, %rdi
	mov	%rdx, %rsi
	mov	%rcx, %rdx
	mov	%r8, %r10
	mov	%r9, %r8
	mov	8(%rsp), %r9
	syscall
	ret
	.size	hss_raw_syscall6, .-hss_raw_syscall6

	.section .note.GNU-stack,"",@progbits
