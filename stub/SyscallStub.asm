.code

PUBLIC SyscallInvoke
SyscallInvoke PROC
    test rdx, rdx
    jz err_sys

    mov r11, rdx
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp + 28h]
    mov r9, [rsp + 30h]

    mov rax, [rsp + 38h]
    mov [rsp + 28h], rax
    mov rax, [rsp + 40h]
    mov [rsp + 30h], rax

    mov eax, ecx
    jmp r11

err_sys:
    mov eax, 0C0000001h
    ret
SyscallInvoke ENDP

END
