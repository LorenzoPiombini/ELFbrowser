#include <stdio.h>
#include "inject.h"
#include "bin.h"

int main(){
	int r = inject_instruction_silent("CIAO_pie",(char *)Hello_word,sizeof(Hello_word)-1);
//	int r = inject_instruction("main",".text",(char*)reboot,sizeof(reboot)-1);
	if(r == -1) return -1;
	return 0;
}
