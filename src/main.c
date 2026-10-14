#include <stdio.h>
#include "inject.h"
#include "bin.h"

int main(int argc, char **argv){
	if(argc < 2){
		printf("i need a target!\n");
		return 0;
	}

	if(argv[1]){
		int r = inject_instruction_silent(argv[1],(char *)Hello_word,sizeof(Hello_word)-1);
		//int r = inject_instruction("CIAO_pie",".text",(char*)reboot,sizeof(reboot)-1);
		if(r == -1) return -1;
	}
	return 0;
}
