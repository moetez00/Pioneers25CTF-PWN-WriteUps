/* compile: gcc -o main main.c -fno-stack-protector
*/ 

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


void setup(){
    setbuf(stdout,0);
    setbuf(stdin,0); 
    setbuf(stderr,0);
}

void win(){
    system("cat banner.txt");
    system("cat flag"); // should be تمت تعبئة الكرش بنجاح 
    // + taswira ken njmt
    // buffer was filled successfully ? 
    
}

void vuln(){
   
    char changeme[9];
    char buf[0x20];
    strcpy(changeme,"changeme");
    printf("Just fill the buffer\n");
    read(0,buf,0x28);
    if(strcmp(changeme,"changeme")!=0)
        win();
    exit(0);

}
void main(){
    setup();
    printf("For better experience please make sure to use fullscreen terminal <3\n");
    int choice;
    printf("Are you ready to solve this insane challenge? [Y=1/N=0]\n");
    scanf("%d",&choice);
    if(choice==1){
        vuln();
    }
    printf("Shame on u!\n");
    exit(0);
}