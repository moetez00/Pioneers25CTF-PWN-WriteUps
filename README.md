# Pioneers25 CTF — PWN Writeups

Collection of PWN challenge writeups, sources, binaries, and solve scripts from **Pioneers25**.

## Repository layout

- Each challenge lives in its own folder.
- Most folders include:
  - `writeup.md` — solution notes
  - `solve.py` — exploit script
  - `main` — provided binary
  - `main.c` / `main.cpp` — source code
  - `Dockerfile` / `docker-compose.yml` — local run environment
  - `libc.so.6`, `ld-linux-x86-64.so.2`, `libseccomp.so.*` — provided runtime deps (when needed)

## Quick start (local)

Many challenges ship with a Docker setup.

```bash
cd "<challenge-folder>"
docker compose up --build
```

If you’re using older Docker Compose:

```bash
cd "<challenge-folder>"
docker-compose up --build
```

## Challenges

| Challenge | Writeup | Solve | Notes |
|---|---|---|---|
| `5959595959` | [writeup.md](5959595959/writeup.md) | [solve.py](5959595959/solve.py) | Includes bundled `libc`/`ld` |
| `ARMBLUSBLUS` | [writeup.md](ARMBLUSBLUS/writeup.md) | [solve.py](ARMBLUSBLUS/solve.py) | C++ binary |
| `Fill me` | [writeup.md](Fill%20me/writeup.md) | [solve.py](Fill%20me/solve.py) | Includes `banner.txt` |
| `Flip Flip Flip` | [writeup.md](Flip%20Flip%20Flip/writeup.md) | [solve.py](Flip%20Flip%20Flip/solve.py) | — |
| `Hope Exploitation` | [writeup.md](Hope%20Exploitation/writeup.md) | [solve.py](Hope%20Exploitation/solve.py) | Includes bundled `libc`/`ld` + `libseccomp` |
| `Who likes assembly anw ?` | [writeup.md](Who%20likes%20assembly%20anw%20%3F/writeup.md) | [solve.py](Who%20likes%20assembly%20anw%20%3F/solve.py) | Includes `libseccomp` |
| `print(xxx);` | [writeup.md](print(xxx)%3B/writeup.md) | — | Contains multiple sub-challenges |

### `print(xxx);` sub-challenges

| Sub-challenge | Writeup | Solve |
|---|---|---|
| `printf(Hello);` | [writeup.md](print(xxx)%3B/%20printf(Hello)%3B%20/writeup.md) | [solve.py](print(xxx)%3B/%20printf(Hello)%3B%20/solve.py) |
| `printf(Revenge)` | [writeup.md](print(xxx)%3B/%20printf(Revenge)/writeup.md) | [solve.py](print(xxx)%3B/%20printf(Revenge)/solve.py) |
| `printf(RevengeRevenge)` | [writeup.md](print(xxx)%3B/%20printf(RevengeRevenge)/writeup.md) | [solve.py](print(xxx)%3B/%20printf(RevengeRevenge)/solve.py) |

## Notes

- These folders may include challenge-provided binaries and libraries intended for local testing.
- If you publish this repository, ensure you’re allowed to redistribute any provided binaries/libs.
