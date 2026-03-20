/*
compile with gcc -o main main.c -Wl,-z,relro,-z,now

*/
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
void (*f)(void * x1)=(void*)0x0;
char string[15];//bsh ywali /bin/sh\x00

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    strcpy(string,"useless_string");
}

void bit_flip() {
    unsigned long long address = 0x0;
    int bit = 0x0;
    printf("> ");
    scanf("%llx", &address);
    scanf("%d", &bit);
    if (bit > 7 || bit < 0) {
        puts("Go back to school lil bro");
        return;
    }
    char byte = *(char*)address;
    byte = (1 << bit) ^ byte;
    *(char*)address = byte;
}

void vuln() {
    unsigned long long address = 0x0;
    printf("&vuln = %p\n", &vuln);
    printf("&system = %p\n", &system);
    printf("&address = %p\n", &address);

    for (int i = 0; i < 3; i++) {
        bit_flip();
    }
}

int main() {
    setup();
    puts("X-OR felt super generous that day");
    vuln();
    return 0;
}

void win(){
    f(string);
}