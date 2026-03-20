/* compile: gcc -o main main.c -no-pie -Wl,-T,custom.ld -Wl,-z,norelro,now
*/ 

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

void setup(){
    setbuf(stdout,0);
    setbuf(stdin,0); 
    setbuf(stderr,0);
    mprotect((void*)(0x403000),0x1000,PROT_READ);

}

void vuln(){
    char name[200];
    char buf[150];
    void* p = name + 0xc8;
    printf("Your secret code : %ld\n",puts);
    printf("Whaat's your naame?\n");
    printf("Whaat?\n");
    printf("Whaaat iss your naaame?\n");
    fgets(buf,150,stdin);
    sprintf(name,"Fank You %s",buf);
    printf(name);
}
void main(){
    setup();
    vuln();
    return;
}