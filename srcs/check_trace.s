check_trace:                    ;return 1 if process is traced and 0 if not traced
    jmp $+4
    db `\x31\x2d`
    mov rbx, rdi
    lea rdi, [rel self_status]
    xor rsi, rsi
    mov rax, SYS_OPEN
    syscall             ; open("/proc/self/status", O_RDONLY)
    mov r8, rax
    mov rdi, r8
    mov rsi, rbx
    mov rdx, PATH_BUFF_SIZE
    mov rax, SYS_READ
    jmp $+4
    db `\x48\x8b`
    syscall             ; read(fd, buff[PATH_BUFF_SIZE], PATH_BUFF_SIZE)
    mov rdx, rax
    sub rdx, no_trace.len
    mov rdi, r8
    mov rax, SYS_CLOSE
    syscall
    xor rax, rax
    check_trace_loop:
    inc rax
    inc rbx
    jmp $+4
    db `\x69\x61`
    lea rdi, [rel no_trace.string]
    mov rsi, rbx
    mov rcx, no_trace.len
    repz cmpsb
    jz no_trace_found

    cmp rax, rdx
    jl check_trace_loop
    xor rax, rax
    ret
    no_trace_found:
    mov rax, 1
    ret