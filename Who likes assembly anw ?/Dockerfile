FROM ubuntu:latest

RUN apt-get update && apt-get install -y socat
RUN apt-get install -y cpulimit && apt-get install -y sudo gdb

WORKDIR /redeacted/flag_dir/
COPY flag ./

WORKDIR /app

RUN useradd -m ctf

COPY main libc.so.6* ld-linux-x86-64.so.2* libseccomp.so.2.5.6 ./

RUN chmod +x main


EXPOSE 10004

CMD socat TCP-LISTEN:10004,reuseaddr,fork EXEC:'timeout 60 ./main'