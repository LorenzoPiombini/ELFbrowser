#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "inject.h"

static void parse_h(struct Elf_h *header, const uint8_t *file);
static void parse_ph(struct Elf_ph_64 *ph, const uint8_t *file, int e_size);
static void parse_sh(struct Elf_sh_64 *sh, const uint8_t *file, int e_size);

const uint8_t return_lens[] = {7,3,7};
const char *Return_instructions[] = {"\xb8\x00\x00\x00\x00\x5d\xc3","\x31\xc0\xc3","\xb8\x00\x00\x00\x00\xc9\xc3",NULL};
const uint8_t padding_lens[] = {12};
const char *padding_instructions[] = {"\x66\xc7\x45\xfc\x05\x00\x66\xc7\x45\xfe\x04\x00",NULL};

/*look for .text in the ELF, and 
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

	unsigned char file[size+1];
	memset(file,0,size+1);

	if(read(fd,file,size) == -1){
		close(fd);
		return -1;
	}

	close(fd);
	fd = -1;

	struct Elf_h eh = {0};
	parse_h(&eh,(const uint8_t*)file);

	struct Elf_ph_64 phs[eh.e_phnum];
	memset(phs,0,eh.e_phnum*eh.e_phentsize);
	parse_ph(phs,(const uint8_t*)file + eh.e_phoff, eh.e_phentsize * eh.e_phnum);
	
	/*extract the .text segment from the file buffer*/
	uint8_t text[phs[3].p_filesz+1];
	size_t new_text_sz = phs[3].p_filesz + inst_size;
	uint8_t NEW_text[new_text_sz + 1];
	memset(text,0,phs[3].p_filesz);
	memset(NEW_text,0,new_text_sz + 1);

	memcpy(text,&file[phs[3].p_offset],phs[3].p_filesz);	

	/*INJECT*/
	uint64_t start = phs[3].p_filesz - 1 ;
	memcpy(NEW_text,text,start);
	memcpy(&NEW_text[start],instruction,inst_size);
	start += inst_size;
	memcpy(&NEW_text[start],&text[phs[3].p_filesz-1],1);
	
	phs[3].p_filesz += inst_size;
	phs[3].p_memsz += inst_size;

	unsigned char new_elf[size + 1];
	memset(new_elf,0,size+ 1);

	ssize_t bwritten = 0;
	memcpy(new_elf,(uint8_t*)&eh,sizeof(eh));
	bwritten += sizeof(eh);
	
	memcpy(&new_elf[bwritten],(uint8_t*)&phs,sizeof(phs));
	bwritten += sizeof(phs);
	
	memcpy(&new_elf[bwritten],&file[bwritten],phs[3].p_offset - bwritten);
	bwritten = phs[3].p_offset;
	
	memcpy(&new_elf[bwritten],NEW_text,new_text_sz);
	bwritten += new_text_sz;

	memcpy(&new_elf[bwritten],&file[bwritten],size - bwritten);
	
	/*write the file*/
	fd = open(target,O_WRONLY | O_TRUNC,flag);
	if(fd == -1) return -1;
	
	int r = write(fd,new_elf,size);
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

	
	unsigned char file[size+1];
	memset(file,0,size+1);

	if(read(fd,file,size) == -1){
		close(fd);
		return -1;
	}

	close(fd);
	fd = -1;
	struct Elf_h eh = {0};
	parse_h(&eh,(const uint8_t*)file);

	struct Elf_ph_64 phs[eh.e_phnum];
	memset(phs,0,eh.e_phnum*eh.e_phentsize);
	parse_ph(phs,(const uint8_t*)file + eh.e_phoff, eh.e_phentsize * eh.e_phnum);

	struct Elf_sh_64 shs[eh.e_shnum];
	memset(shs,0,eh.e_shnum * eh.e_shentsize);
	parse_sh(shs,(const uint8_t*)file + eh.e_shoff, eh.e_shentsize * eh.e_shnum);

	/* get shared string table*/
	int sz = shs[eh.e_shstrndx].sh_size;
	unsigned char strtbl[sz + 1];
	memset(strtbl,0,sz + 1);
	memcpy(strtbl,&file[shs[eh.e_shstrndx].sh_offset],sz);
	
	/*read section header to understand where to inject the code
		 you can inject in .init or .text sections */

	uint16_t target_index = 0;
	size_t seg_name_sz = strlen(section_to_inject); 
	for(uint16_t i = 0; i < eh.e_shnum; i++){
		if(!shs[i].sh_name) continue;
		if(strlen(&strtbl[shs[i].sh_name]) != seg_name_sz) continue;
		
		if(strncmp(&strtbl[shs[i].sh_name],section_to_inject,seg_name_sz) == 0){
			target_index = i;
			break;
		}
	}

	fd = open(target,O_WRONLY,flag);
	if(fd == -1){
		printf("cannot create the program\n");
		return 0;
	}

	if(lseek(fd,shs[target_index].sh_offset,SEEK_SET) == -1){
		close(fd);
		return 1;
	}

	/*INJECTION*/
	int r = write(fd,instruction,inst_size);
	close(fd);

	if(r == -1) return -1;
	return 0;
}


static void parse_h(struct Elf_h *header, const uint8_t *file)
{
	memcpy((uint8_t*)header,file,16);	
	memcpy((uint8_t*)header + 16,file + 16,64 - 16);
}

static void parse_ph(struct Elf_ph_64 *ph, const uint8_t *file, int e_size)
{
	memcpy((uint8_t*)ph,file,e_size);
}

static void parse_sh(struct Elf_sh_64 *sh, const uint8_t *file, int e_size)
{
	memcpy((uint8_t*)sh,file,e_size);
}
