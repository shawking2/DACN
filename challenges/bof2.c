#include <stdio.h>
void bof(){
	char s[8];
	puts("hello");
	fgets(s, 0x10, stdin);
}
void bof2(){
	char t[20];
	puts("test3");
	fgets(t, 0x110, stdin);
}
int main(){
	puts("hello 1234");
	bof();
}
