.code

EXTERN StubMainWorker : PROC

PUBLIC StubEntryPoint
StubEntryPoint PROC
    sub rsp, 48h
    lea rcx, [rsp + 20h]
    call StubMainWorker
    test al, al
    jz fail_exit

    mov rax, [rsp + 20h]
    mov rdx, [rsp + 28h]
    add rsp, 48h
    test rdx, rdx
    jz direct_dispatch
    sub rsp, rdx

direct_dispatch:
    xor ecx, ecx
    xor edx, edx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11

    mov [rsp - 8], rax
    xor eax, eax
    jmp qword ptr [rsp - 8]

fail_exit:
    add rsp, 48h
    xor eax, eax
    ret
StubEntryPoint ENDP

PUBLIC __chkstk
__chkstk PROC
    push rcx
    push r10
    push r11
    push rax
    lea r10, [rsp + 28h]
probe_loop:
    sub r10, 1000h
    test dword ptr [r10], 0
    sub rax, 1000h
    cmp rax, 1000h
    ja probe_loop
    pop rax
    pop r11
    pop r10
    pop rcx
    ret
__chkstk ENDP

END
