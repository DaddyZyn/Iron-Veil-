.code

PUBLIC SyscallInvoke
SyscallInvoke PROC
    mov eax, ecx
    mov r11, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp + 28h]
    mov r9, [rsp + 30h]

    sub rsp, 48h

    mov rax, [rsp + 80h]
    mov [rsp + 28h], rax
    mov rax, [rsp + 88h]
    mov [rsp + 30h], rax
    mov rax, [rsp + 90h]
    mov [rsp + 38h], rax
    mov rax, [rsp + 98h]
    mov [rsp + 40h], rax

    mov eax, ecx

    test r11, r11
    jz direct_sys

    call r11
    jmp finish_sys

direct_sys:
    syscall

finish_sys:
    add rsp, 48h
    ret
SyscallInvoke ENDP

END
