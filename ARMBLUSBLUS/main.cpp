/*chall name: 
compile with gcc -o main main.c -Wl,-z,relro,-z,now

*/
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include <string>
#include <iostream>

using namespace std;

void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}


void vuln() {

    char buf[0x40];
    cout<<"Enter your inputs: ";
    cin>>buf;
    
    cout<<"You entered: "<<buf<<endl;
    return;
}


int main() {
    setup();
    vuln();
    return 0;
}

void win(int x10){
    string s="cat flag";
    if(x10==0xdeadbeef){
        system(s.c_str());
    }
}