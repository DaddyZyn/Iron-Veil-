.code

EXTERN StubMainWorker : PROC

StubEntryPoint PROC
    clc
    jnc stage0
    db 0E8h, 012h, 034h, 056h, 078h

stage0:
    push rcx
    push rdx
    push r8
    push r9
    sub rsp, 28h

    mov r10, gs:[30h]
    test r10, r10
    jz dead_trap

    stc
    jc stage1
    db 0EBh, 0FFh

stage1:
    mov r10, 04F8A2B1C7E9D3F50h
    rol r10, 11
    xor r10d, 07C1B2A84h
    not r10

    stc
    jc stage2
    db 0E8h, 0AAh, 055h, 0AAh, 055h

stage2:
    lea r11, StubMainWorker
    xor r11, 055AA55AAh
    rol r10, 3
    xor r11, 055AA55AAh

    clc
    jnc stage3
    db 0E9h, 044h, 033h, 022h, 011h

stage3:
    call r11

    add rsp, 28h
    pop r9
    pop r8
    pop rdx
    pop rcx

    test rax, rax
    jz dead_trap

    stc
    jc stage4
    db 0EBh, 005h

stage4:
    clc
    jnc transfer_oep
    db 0E8h, 000h, 000h, 000h, 000h

transfer_oep:
    mov r10, rax
    bswap r10
    bswap r10
    push r10
    xor r10, r10
    ret

dead_trap:
    xor eax, eax
    ret
StubEntryPoint ENDP

IronVeilDecoyCipher PROC
    push rbx
    push rsi
    push rdi
    mov eax, 1337h
    rol eax, 5
    xor eax, 0A5A5A5A5h
    bswap eax
    pop rdi
    pop rsi
    pop rbx
    ret
IronVeilDecoyCipher ENDP

IronVeilDecoyLicense PROC
    push rbx
    xor eax, eax
    cpuid
    test eax, eax
    setnz al
    pop rbx
    ret
IronVeilDecoyLicense ENDP


PUBLIC __chkstk
__chkstk PROC
    push rcx
    push r10
    push r11
    lea r10, [rsp + 20h]
probe_loop:
    sub r10, 1000h
    test dword ptr [r10], 0
    sub rax, 1000h
    cmp rax, 1000h
    ja probe_loop
    pop r11
    pop r10
    pop rcx
    ret
__chkstk ENDP

END
