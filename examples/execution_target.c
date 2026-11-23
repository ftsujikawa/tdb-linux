#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

extern void call_store(int *value);
extern void call_exit(int code);
extern void exit_by_syscall(int code);
extern void illegal_instruction(void);
extern void call_through_memory(int *value);

/* Exact instruction boundaries for the machine-level stepping tests. */
__asm__(
    ".text\n"
    ".globl call_store\n"
    ".type call_store, @function\n"
    "call_store:\n"
    "subq $8, %rsp\n"
    "leaq store_value(%rip), %rax\n"
    ".globl indirect_call\n"
    "indirect_call:\n"
    "call *%rax\n"
    ".globl after_indirect_call\n"
    "after_indirect_call:\n"
    "addq $8, %rsp\n"
    "ret\n"
    ".size call_store, .-call_store\n"
    ".globl store_value\n"
    ".type store_value, @function\n"
    "store_value:\n"
    "movl $17, (%rdi)\n"
    "ret\n"
    ".size store_value, .-store_value\n"
    ".globl call_exit\n"
    ".type call_exit, @function\n"
    "call_exit:\n"
    "subq $8, %rsp\n"
    ".globl exit_call\n"
    "exit_call:\n"
    "call _exit@PLT\n"
    "addq $8, %rsp\n"
    "ret\n"
    ".size call_exit, .-call_exit\n"
    ".globl exit_by_syscall\n"
    ".type exit_by_syscall, @function\n"
    "exit_by_syscall:\n"
    "movl $60, %eax\n"
    ".globl exit_syscall\n"
    "exit_syscall:\n"
    "syscall\n"
    ".size exit_by_syscall, .-exit_by_syscall\n"
    ".globl illegal_instruction\n"
    ".type illegal_instruction, @function\n"
    "illegal_instruction:\n"
    "ud2\n"
    "ret\n"
    ".size illegal_instruction, .-illegal_instruction\n"
    ".globl call_through_memory\n"
    ".type call_through_memory, @function\n"
    "call_through_memory:\n"
    "subq $136, %rsp\n"
    "leaq store_value(%rip), %rax\n"
    "movq %rax, (%rsp)\n"
    "movq %rax, 8(%rsp)\n"
    "movq %rax, 128(%rsp)\n"
    "xorl %ecx, %ecx\n"
    ".globl call_sib, call_disp8, call_disp32, call_rip_relative, call_no_base, memory_calls_end\n"
    "call_sib:\n"
    "call *(%rsp,%rcx,8)\n"
    "call_disp8:\n"
    "call *8(%rsp)\n"
    "call_disp32:\n"
    "call *128(%rsp)\n"
    "call_rip_relative:\n"
    "call *store_pointer(%rip)\n"
    "call_no_base:\n"
    "call *store_pointer(,%rcx,8)\n"
    "memory_calls_end:\n"
    "addq $136, %rsp\n"
    "ret\n"
    ".size call_through_memory, .-call_through_memory\n"
    ".pushsection .rodata\n"
    ".p2align 3\n"
    "store_pointer: .quad store_value\n"
    ".popsection\n"
);

int main(int argc, char **argv)
{
    if (argc > 1 && argv[1][0] == 'e') {
        call_exit(7);
        return 2;
    }

    if (argc > 1 && argv[1][0] == 's') {
        exit_by_syscall(9); /* step into code without DWARF */
        return 2;
    }

    if (argc > 1 && argv[1][0] == 'i') {
        illegal_instruction();
        return 2;
    }

    if (argc > 1 && argv[1][0] == 'f') {
        pid_t child = fork();
        if (child == 0) {
            raise(SIGKILL);
            _exit(2);
        }
        int status;
        return child < 0 || waitpid(child, &status, 0) != child ||
               !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL;
    }

    int values[4] = {0};
    if (argc > 1 && argv[1][0] == 'm') {
        call_through_memory(values);
    } else {
        call_store(values);
    }
    return values[0] == 17 ? 0 : 1;
}
