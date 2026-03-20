/* compile: gcc -o main main.c -lseccomp  -Wl,-z,relro,-z,now -pie -no-pie -fno-stack-protector
no pie,full relro,no canary
ret2shellcode
flag path should be sth unknown / random idk 
*/ 
#include <unistd.h>
#include <string.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#define _GNU_SOURCE


void install_seccomp() {
    scmp_filter_ctx ctx;
    int r;

    /* Default: kill the process on an unallowed syscall */
    ctx = seccomp_init(SCMP_ACT_KILL); 
    if (!ctx) {
        perror("seccomp_init");
        exit(1);
    }

    /* Allow basic syscalls needed by most C programs */
    #define ALLOW(s) do { r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(s), 0); \
                          if (r < 0) { fprintf(stderr, "rule add %s failed: %d\n", #s, r); exit(1); } } while (0)

    ALLOW(write);
    ALLOW(read);
    ALLOW(lseek);
    ALLOW(open);
    ALLOW(exit);
    ALLOW(exit_group);
    ALLOW(getpid);


    #undef ALLOW


    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        exit(1);
    }

    seccomp_release(ctx);
}
uint64_t secure_random(void) {
    uint64_t x;
    FILE* fd = fopen("/dev/urandom", "r");
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    if (fread(&x, 1, sizeof(x), fd) != sizeof(x)) {
        perror("read");
        exit(1);
    }
    fclose(fd);
    return (x % 0xFFFFFF) + 1;
}
void setup(){
    char buf[90];
    buf[0]  = '/';
    buf[1]  = 'r';
    buf[2]  = 'e';
    buf[3]  = 'd';
    buf[4]  = 'e';
    buf[5]  = 'a';
    buf[6]  = 'c';
    buf[7]  = 't';
    buf[8]  = 'e';
    buf[9]  = 'd';
    buf[10] = '/';
    buf[11] = 'f';
    buf[12] = 'l';
    buf[13] = 'a';
    buf[14] = 'g';
    buf[15] = '_';
    buf[16] = 'p';
    buf[17] = 'a';
    buf[18] = 't';
    buf[19] = 'h';
    buf[20] = '/';
    buf[21] = 'f';
    buf[22] = 'l';
    buf[23] = 'a';
    buf[24] = 'g';
    buf[25] = '\x00';
    FILE* fd=fopen(buf,"r");
    memset(buf,0,90);
    fread(buf,1,90,fd);
    fclose(fd);
    mmap(
        (void*)0x700000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        -1,
        0
    ); 
    long int addr = secure_random()<<0x10;
    mmap((void*)addr,0x1000000,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED,-1,0);
    int translate=secure_random();
    memcpy((void*)(addr+translate),buf,90);
    memset(buf,0,90);
    install_seccomp();
    setbuf(stdout,0);
    setbuf(stdin,0); 
    setbuf(stderr,0);
    
}
void vuln(){
    char buf[32];
    read(0,buf,300);
    return;
}
void main(){
    setup();
    vuln();
    return;
}

