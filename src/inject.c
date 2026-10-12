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

	struct Elf_sh_64 shs[eh.e_shnum];
	memset(shs,0,eh.e_shnum * eh.e_shentsize);
	parse_sh(shs,(const uint8_t*)file + eh.e_shoff, eh.e_shentsize * eh.e_shnum);

	/* get shared string table*/
	int sz = shs[eh.e_shstrndx].sh_size;
	unsigned char strtbl[sz + 1];
	memset(strtbl,0,sz + 1);
	memcpy(strtbl,&file[shs[eh.e_shstrndx].sh_offset],sz);
	
	/*read section header to understand where to inject the code
		 look for .text sections */

	uint16_t text_data_index = 0;
	size_t text_seg_name_sz = strlen(TEXT); 
	for(uint16_t i = 0; i < eh.e_shnum; i++){
		if(!shs[i].sh_name) continue;
		if(strlen(&strtbl[shs[i].sh_name]) != text_seg_name_sz) continue;
		
		if(strncmp(&strtbl[shs[i].sh_name],TEXT,text_seg_name_sz) == 0){
			/*.text info */
			text_data_index = i;
			break;
		}
	}

	
	/*extract the .text segment from the file buffer*/
	uint8_t text[shs[text_data_index].sh_size+1];
	size_t new_text_sz = shs[text_data_index].sh_size + inst_size;
	uint8_t NEW_text[new_text_sz + 1];
	memset(text,0,shs[text_data_index].sh_size+1);
	memset(NEW_text,0,new_text_sz + 1);

	memcpy(text,&file[shs[text_data_index].sh_offset],shs[text_data_index].sh_size);	

	int j = 0;
	while(Return_instructions[j]){
		uint64_t start = shs[text_data_index].sh_size - return_lens[j];
		if(memcmp(&text[start],
				Return_instructions[j],
				return_lens[j]) == 0){
			/*start-1 is where to inject!*/
			memcpy(NEW_text,text,start);
			memcpy(&NEW_text[start],instruction,inst_size);
			start += inst_size;
			memcpy(&NEW_text[start],Return_instructions[j],return_lens[j]);
			break;
		}
		j++;
	}
	
	int arr[eh.e_phnum];
	memset(arr,0,eh.e_phnum*sizeof(int));
	int sum = 0;
	for(uint16_t i = text_data_index + 1; i < eh.e_shnum; i++){
		for(uint16_t j = 0; j < eh.e_phnum; j++){
			if(phs[j].p_offset == shs[i].sh_offset){	
				if(arr[j]) continue;
				arr[j]++;
				off_t a = ((phs[j].p_offset + inst_size) + phs[j].p_align - 1) & ~(phs[j].p_align -1);
				sum += (a - (phs[j].p_offset + inst_size));
				printf("(%s) new program header offset is %ld, was %ld, it needs to be %ld\n",phs[j].p_offset + inst_size,phs[j].p_offset,a);
			}  

		}
	}

	printf("you need %d extra bytes\n",sum);
#if 0
		int dif = (((shs[i].sh_offset + inst_size) + (shs[i].sh_addralign -1)) & ~(shs[i].sh_addralign -1)) - shs[i].sh_offset ;	
		printf("you need %d more bytes to make %s aligned.\n",dif,&strtbl[shs[i].sh_name]);
	
	
	while(i < sh_num){
		uint32_t sh_name = 0;	
		
		memcpy(&sh_name,&cpy[bread],sizeof(uint32_t));
		if(!sh_name){
			bread += 64;
			i++;
			continue;
		}

		
		if(strlen(INIT) == strlen(&strtbl[sh_name])){
			if(strncmp(INIT,&strtbl[sh_name],strlen(INIT)) == 0){
				memcpy(&__init_offset,&cpy[bread+0x18],sizeof(off_t));
				if(__init_offset == 0) return -1;

				bread += 64;
				i++;
				continue;

			}
		}

		if(strlen(FINI) == strlen(&strtbl[sh_name])){
			if(strncmp(FINI,&strtbl[sh_name],strlen(FINI)) == 0){
				memcpy(&__fini_offset,&cpy[bread+0x18],sizeof(off_t));
				if(__fini_offset == 0) return -1;
				bread += 64;
				i++;
				continue;
			}
		}
		if(strlen(RODATA) == strlen(&strtbl[sh_name])){
			if(strncmp(RODATA,&strtbl[sh_name],strlen(RODATA)) == 0){
				memcpy(&__ro_data_offset,&cpy[bread+0x18],sizeof(off_t));
				if(__ro_data_offset == 0) return -1;
				bread += 64;
				i++;
				continue;
			}
		}

		if(strlen(EHFRAME_HDR) == strlen(&strtbl[sh_name])){
		if(strncmp(EHFRAME_HDR,&strtbl[sh_name],strlen(EHFRAME_HDR)) == 0){
			memcpy(&__eh_frame_hdr_offset,&cpy[bread+0x18],sizeof(off_t));
			if(__eh_frame_hdr_offset == 0) return -1;
			bread += 64;
			i++;
			continue;
		}
		}


		if(strncmp(EHFRAME,&strtbl[sh_name],strlen(EHFRAME)) == 0){
			memcpy(&__eh_frame_offset,&cpy[bread+0x18],sizeof(off_t));
			if(__eh_frame_offset == 0) return -1;
			bread += 64;
			i++;
			continue;
		}

		if(strlen(INIT_ARRAY) == strlen(&strtbl[sh_name])){
		if(strncmp(INIT_ARRAY,&strtbl[sh_name],strlen(INIT_ARRAY)) == 0){
			memcpy(&__init_arr_offset,&cpy[bread+0x18],sizeof(off_t));
			if(__init_arr_offset == 0) return -1;
			bread += 64;
			i++;
			continue;
		}
		}

		if(strlen(FINI_ARRAY) == strlen(&strtbl[sh_name])){
		if(strncmp(FINI_ARRAY,&strtbl[sh_name],strlen(FINI_ARRAY)) == 0){
			memcpy(&__fini_arr_offset,&cpy[bread+0x18],sizeof(off_t));
			if(__fini_arr_offset == 0) return -1;
			bread += 64;
			i++;
			continue;
		}
		}


		if(strlen(DYNAMIC) == strlen(&strtbl[sh_name])){
		if(strncmp(DYNAMIC,&strtbl[sh_name],strlen(DYNAMIC)) == 0){
			memcpy(&__dynamic_offset,&cpy[bread+0x18],sizeof(off_t));
			if(__dynamic_offset == 0) return -1;

			bread += 64;
			i++;
			continue;
		}
		}

		if(strlen(TEXT) == strlen(&strtbl[sh_name])){
		if(strncmp(TEXT,&strtbl[sh_name],strlen(TEXT)) == 0){
			__text_sh_start = bread;
			memcpy(&__text_offset,&cpy[bread+0x18],sizeof(off_t));
			if(__text_offset == 0) return -1;

			memcpy(&__text_sz,&cpy[bread+0x20],8);
			if(__text_sz == 0) return -1;
		}
		}

		bread += 64;
		i++;
	}	



	/*change the offset in program header table*/
	j = 0;
	ssize_t ph_bread = program_header_start;
	off_t padding_before_rodata = 0;
	off_t __new_rodata_offset = 0;
	while(j < ph_num){
		off_t old = 0;
		memcpy(&old,&cpy[ph_bread+0x08],sizeof(off_t));
/*
		if(old > __text_offset){
			if(old == __ro_data_offset){

				off_t new = ((old + (off_t) inst_size) + 15) & ~15;
				memcpy(&cpy[ph_bread+0x08],&new,sizeof(off_t));

				__new_rodata_offset = new;
				padding_before_rodata = new - old - (off_t)inst_size;
			}
			
			if(old == __init_arr_offset){
				old =  __new_rodata_offset + (old  - __ro_data_offset);
				memcpy(&cpy[ph_bread+0x08],&old,sizeof(off_t));
			}

			if(old == __dynamic_offset){
				old =  __new_rodata_offset + (old  - __ro_data_offset);
				memcpy(&cpy[ph_bread+0x08],&old,sizeof(off_t));
			}

			if(old == __eh_frame_hdr_offset){
				old =  __new_rodata_offset + (old  - __ro_data_offset);
				memcpy(&cpy[ph_bread+0x08],&old,sizeof(off_t));
			}

		}

*/
		if(old == __init_offset){
			memcpy(&cpy[ph_bread+0x20],&__new_text_sz,8);

		}
		ph_bread += (ssize_t)program_header_entry;
		j++;
	}

	/*build the new elf*/
	int new_elf_size = size + inst_size;
	unsigned char new_elf[new_elf_size + 1];
	memset(new_elf,0,new_elf_size + 1);


	uint8_t pad = 0;
	memcpy(new_elf,cpy,__text_offset);

	memcpy(&new_elf[__text_offset],__NEW_text,__new_text_sz);
	memcpy(&new_elf[__new_text_sz+__text_offset],
			&cpy[__text_offset+__text_sz],
			size - (__text_offset +__text_sz));

	section_header_start += (off_t)inst_size;
	memcpy(&new_elf[SHOFF],&section_header_start,sizeof(off_t));

	/*write the file*/
	fd = open(target,O_WRONLY | O_TRUNC,flag);
	if(fd == -1) return -1;
	
	int r = write(fd,new_elf,new_elf_size);
	close(fd);
		
	if(r == -1) return -1;
#endif
	return 0;
}
#if 0
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

#endif

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
