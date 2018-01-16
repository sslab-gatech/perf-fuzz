#ifndef _HAVE_AFL_AS_H
#define _HAVE_AFL_AS_H

#include "config.h"
#include "types.h"

static const u8* trampoline_fmt_32 = "";

static const u8* trampoline_fmt_64 = 

    "\n"
    "/* --- AFL TRAMPOLINE (64-BIT) --- */\n"
    "\n"
    ".align 4\n"
    "\n"
    "leaq -(128+24)(%%rsp), %%rsp\n"
    "movq %%rdx,  0(%%rsp)\n"
    "movq %%rcx,  8(%%rsp)\n"
    "movq %%rax, 16(%%rsp)\n"
    "movq $0x%08x, %%rcx\n"
    "call __afl_maybe_log\n"
    "movq 16(%%rsp), %%rax\n"
    "movq  8(%%rsp), %%rcx\n"
    "movq  0(%%rsp), %%rdx\n"
    "leaq (128+24)(%%rsp), %%rsp\n"
    "\n"
    "/* --- END --- */\n"
    "\n";

static const u8* main_payload_32 = "";
static const u8* afl_main_32 = "";
static const u8* afl_may_log_32 = "";
static const u8* afl_timeout_32 = "";
static const u8* afl_sighandler_32 = "";
static const u8* afl_cleanup_32 = "";
static const u8* afl_kernel_cleanup_32 = "";

#ifdef __APPLE__
#  define CALL_L64(str)		"call _" str "\n"
#else
#  define CALL_L64(str)		"call " str "@PLT\n"
#endif /* ^__APPLE__ */

static const u8* afl_main_64 = 
    
    "\n"
    "/* --- afl_main PAYLOAD (64-BIT) --- */\n"
    "\n"
    ".text\n"
    ".att_syntax\n"
    ".code64\n"
    ".align 8\n"
    "\t.globl\tmain\n"
    "\t.type\tmain, @function\n"
    "\n"
    "main:\n"
    "\n"
    "  pushq %r12\n"
    "  pushq %r13\n"
    "  pushq %r14\n"
    "  pushq %r15\n"
    "  movq  %rsp, %r12\n"
    "  subq  $16, %rsp\n"
    "  andq  $0xfffffffffffffff0, %rsp\n"
    "\n"
    "  movq %rdi, %r13\n"
    "  movq %rsi, %r14\n"
    "  movq %rdx, %r15\n"
    "\n"

    "  movq $10, %rdi\n"
    "  leaq __afl_timeout, %rsi\n"
    CALL_L64("signal") /* SIGUSR1 indicates we are timeout */

    "  movq $11, %rdi\n"
    "  leaq __afl_sighandler, %rsi\n"
    CALL_L64("signal") /* SIGSEGV needs to be carefully handled */

    "  movq $6, %rdi\n"
    "  leaq __afl_sighandler, %rsi\n"
    CALL_L64("signal") /* SIGSEGV needs to be carefully handled */

    "  movq $4, %rdi\n"
    "  leaq __afl_sighandler, %rsi\n"
    CALL_L64("signal") /* SIGSEGV needs to be carefully handled */

    "\n"
    "  leaq .AFL_SHM_ENV(%rip), %rdi\n"
    CALL_L64("getenv")
    "\n"
    "  testq %rax, %rax\n"
    "  je    __afl_setup_abort\n"
    "\n"
    "  movq  %rax, %rdi\n"
    CALL_L64("atoi")
    "\n"
    "  xorq %rdx, %rdx   /* shmat flags    */\n"
    "  xorq %rsi, %rsi   /* requested addr */\n"
    "  movq %rax, %rdi   /* SHM ID         */\n"
    CALL_L64("shmat")
    "\n"
    "  cmpq $-1, %rax\n"
    "  je   __afl_setup_abort\n"
    "\n"
    "  /* Store the address of the SHM region. */\n"
    "\n"
    "  movq %rax, %rdx\n"
    "  movq %rax, __afl_area_ptr(%rip)\n"
    "\n"
    "  movq __afl_global_area_ptr@GOTPCREL(%rip), %rdx\n"
    "  movq %rax, (%rdx)\n"
    "  movq %rax, %rdx\n"
    "\n"
    "__afl_forkserver:\n"
    "\n"
    "\n"
    "  /* Enter the fork server mode to avoid the overhead of execve() calls. We\n"
    "     push rdx (area ptr) twice to keep stack alignment neat. */\n"
    "\n"
    "  pushq %rdx\n"
    "  movq %rsp, __afl_child_status(%rip)\n"
    "  pushq %rdx\n"
    "  movq %rsp, __afl_in_cleanup(%rip)\n"

    "\n"
    "  /* Phone home and tell the parent that we're OK. (Note that signals with\n"
    "     no SA_RESTART will mess it up). If this fails, assume that the fd is\n"
    "     closed because we were execve()d from an instrumented binary, or because\n"
    "     the parent doesn't want to use the fork server. */\n"
    "\n"
    "  movq $4, %rdx               /* length    */\n"
    "  leaq __afl_temp(%rip), %rsi /* data      */\n"
    "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi       /* file desc */\n"
    CALL_L64("write")
    "\n"
    "  cmpq $4, %rax\n"
    "  jne __afl_fork_resume\n"
    "\n"
   
    /* set status to 0 */
    // "  movq __afl_child_status(%rip), %rdx\n"

    "__afl_fork_wait_loop:\n"
    "\n"
    "  /* Wait for parent by reading from the pipe. Abort if read fails. */\n"
    "\n"

    "  leaq __afl_env(%rip), %rdi\n"
    "  movq $1, %rsi\n"
    CALL_L64("__sigsetjmp")
    "\n"

    "  movq $4, %rdx               /* length    */\n"
    "  leaq __afl_temp(%rip), %rsi /* data      */\n"
    "  movq $" STRINGIFY(FORKSRV_FD) ", %rdi             /* file desc */\n"
    CALL_L64("read")
    "  cmpq $4, %rax\n"
    "  jne  __afl_die\n"
    "\n"

    "  movq __afl_in_cleanup(%rip), %rdx\n"
    "  movl $0, (%rdx)\n"

    "  leaq __afl_snapshot_arg(%rip), %rsi\n"

    "  leaq __afl_kernel_cleanup(%rip), %rdi\n"
    "  movq %rdi, (%rsi)\n"
    "  addq $8, %rsi\n"

    "  movq __afl_area_ptr(%rip), %rdi\n"
    "  movq %rdi, (%rsi)\n"
    "  addq $8, %rsi\n"

    "  movq $" STRINGIFY(MAP_SIZE) ", (%rsi)\n"

    "  movq $329, %rdi\n"
    "  movq $0, %rsi\n"
    "  leaq __afl_snapshot_arg(%rip), %rdx\n"
    CALL_L64("syscall")
    
    "__afl_fork_resume:\n"
    "\n"

    "  movq %r13, %rdi\n"
    "  movq %r14, %rsi\n"
    "  movq %r15, %rdx\n"
    "\n"
    "  call __do_main\n"
    "\n"

    "  movq $0, %rdi\n"
    "  call __afl_cleanup\n"
    "\n"

    "  popq %rdx\n"
    "  popq %rdx\n"
    "\n"
    // "  xorq %rax, %rax\n"
    "__afl_epilogue:\n"
    "\n"
    "  movq %r12, %rsp\n"
    "  popq %r15\n"
    "  popq %r14\n"
    "  popq %r13\n"
    "  popq %r12\n"
    "  ret\n"
    "__afl_die:\n"
    "\n"
    "  xorq %rax, %rax\n"
    CALL_L64("_exit")
    "\n"
    "__afl_setup_abort:\n"
    "\n"
    "  movq %r13, %rdi\n"
    "  movq %r14, %rsi\n"
    "  movq %r15, %rdx\n"
    "\n"
    "  call __do_main\n"
    "\n"
    "  jmp __afl_epilogue\n"
    "\n"
    ".align 8\n";

static const u8* afl_timeout_64 = 
    "\n"
    "/* --- afl_timeout PAYLOAD (64-BIT) --- */\n"
    "\n"
    ".text\n"
    ".att_syntax\n"
    ".code64\n"
    ".align 8\n"
    "\n"
    "__afl_timeout:\n"
    "\n"

    "  pushq %rdx\n"
    "  movq __afl_in_cleanup(%rip), %rdx\n" 
    "  cmpl $0, (%rdx)\n"
    "  popq %rdx\n"
    "  jnz __afl_timeout_ret\n"

    "  movq $0, %rdi\n"
    "  call __afl_cleanup\n"
    "\n"
    "__afl_timeout_ret:\n"
    "  ret\n";


static const u8* afl_sighandler_64 = 
    "\n"
    "/* --- afl_sighandler PAYLOAD (64-BIT) --- */\n"
    "\n"
    ".text\n"
    ".att_syntax\n"
    ".code64\n"
    ".align 8\n"
    "\n"
    "__afl_sighandler:\n"
    "\n"

    "  movq $139, %rdi\n"
    "  call __afl_cleanup\n"
    "\n"

    "ret\n";

static const u8* afl_kernel_cleanup_64 = 
    "\n"
    "/* --- afl_kernel_cleanup PAYLOAD (64-BIT) --- */\n"
    "\n"
    ".text\n"
    ".att_syntax\n"
    ".code64\n"
    ".align 8\n"
    "\n"
    "__afl_kernel_cleanup:\n"
    "\n"

    "  movq __afl_in_cleanup(%rip), %rdx\n"
    "  movl $1, (%rdx)\n"
    
    "  movq __afl_child_status(%rip), %rdx\n"
    "  movq $0, (%rdx)\n"

    "  movq $329, %rdi\n"
    "  movq $1, %rsi\n"
    "  movq $0, %rdx\n"
    CALL_L64("syscall")
    "\n"

    "  movq $4, %rdx               /* length    */\n"
    "  movq __afl_child_status(%rip), %rsi /* data      */\n"
    "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi         /* file desc */\n"
    CALL_L64("write")
    "\n"

    "  leaq __afl_env(%rip), %rdi\n"
    "  movq $1, %rsi\n"
    CALL_L64("siglongjmp")
    "\n"

    "ret\n";


static const u8* afl_cleanup_64 = 
    "\n"
    "/* --- afl_cleanup PAYLOAD (64-BIT) --- */\n"
    "\n"
    ".text\n"
    ".att_syntax\n"
    ".code64\n"
    ".align 8\n"
    "\n"
    "__afl_cleanup:\n"
    "\n"

    "  movq __afl_in_cleanup(%rip), %rdx\n"
    "  movl $1, (%rdx)\n"

    "  movq __afl_child_status(%rip), %rdx\n"
    "  movl %edi, (%rdx)\n"

    "  movq $329, %rdi\n"
    "  movq $1, %rsi\n"
    "  movq $0, %rdx\n"
    CALL_L64("syscall")
    "\n"

    "  movq $4, %rdx               /* length    */\n"
    "  movq __afl_child_status(%rip), %rsi /* data      */\n"
    "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi         /* file desc */\n"
    CALL_L64("write")
    "\n"

    // "  movl $0, __afl_in_cleanup(%rip)\n"
    // "\n"

    "  leaq __afl_env(%rip), %rdi\n"
    "  movq $1, %rsi\n"
    CALL_L64("siglongjmp")
    "\n"

    "ret\n";

static const u8* afl_may_log_64 = 
    
    "\n"
    "/* --- afl_may_log PAYLOAD (64-BIT) --- */\n"
    "\n"
    ".text\n"
    ".att_syntax\n"
    ".code64\n"
    ".align 8\n"
    "\n"
    "__afl_maybe_log:\n"
    "  lahf\n"
    "  seto    %al\n"
    "\n"
    "  /* Check if SHM region is already mapped. */\n"
    "\n"
    "  movq  __afl_area_ptr(%rip), %rdx\n"
    "  testq %rdx, %rdx\n"
    "  je  __afl_try_setup\n"

    "\n"
    "__afl_store:\n"
    "\n"
    "  /* Calculate and store hit for the code location specified in rcx. */\n"
    "\n"
    "  xorq __afl_prev_loc(%rip), %rcx\n"
    "  xorq %rcx, __afl_prev_loc(%rip)\n"
    "  shrq $1, __afl_prev_loc(%rip)\n"
    "\n"
    "  incb (%rdx, %rcx, 1)\n"
    "  jmp __afl_return\n"
    "\n"

    "\n"
    "__afl_try_setup:"
    "  movq  __afl_global_area_ptr@GOTPCREL(%rip), %rdx\n"
    "  movq  (%rdx), %rdx\n"
    "  testq %rdx, %rdx\n"
    "  je    __afl_return\n"
    "  movq %rdx, __afl_area_ptr(%rip)\n"
    "  jmp  __afl_store\n" 

    "\n"
    "__afl_return:\n"
    "\n"
    "  addb $127, %al\n"
    "  sahf\n"
    "  ret\n"
    "\n"
    ".align 8\n"
    "\n"

    ".AFL_VARS:\n"
    "\n"
    "  .lcomm   __afl_area_ptr, 8\n"
#ifndef COVERAGE_ONLY
    "  .lcomm   __afl_prev_loc, 8\n"
#endif /* !COVERAGE_ONLY */
    "  .lcomm   __afl_fork_pid, 4\n"
    "  .lcomm   __afl_temp, 4\n"
    "  .lcomm   __afl_env, 256\n"
    "  .lcomm   __afl_snapshot_arg, 24\n"
    // "  .lcomm   __afl_setup_failure, 1\n"
    "  .lcomm   __afl_child_status, 8\n"
    "  .lcomm   __afl_in_cleanup, 8\n"

    "  .comm   __afl_global_area_ptr, 8, 8\n"
    "\n"
    ".AFL_SHM_ENV:\n"
    "  .asciz \"" SHM_ENV_VAR "\"\n"
    "\n"
    ".AFL_STRING:\n"
    "  .asciz \"" "alibabaalibaba" "\"\n"
    "\n"
    "/* --- END --- */\n"
    "\n";

#endif /* !_HAVE_AFL_AS_H */



