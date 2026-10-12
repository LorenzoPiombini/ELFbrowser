#ifndef __INJECT_H_
#define __INJECT_H_

#define TEXT 		".text"	
#define INIT 		".init"	
#define FINI 		".fini"	
#define RODATA 		".rodata"	
#define EHFRAME 	"eh_frame"
#define DYNAMIC 	".dynamic"
#define EHFRAME_HDR ".eh_frame_hdr" 
#define INIT_ARRAY 	".init_array" 
#define FINI_ARRAY 	".fini_array"
#define GOT 		".got" 
#define DATA 		".data"
#define BSS 		".bss" 
#define COMMENTS 	".comment"
#define SYMTAB 		".symtab" 

#include <stdint.h>
struct Elf_h{
	uint8_t 	e_ident[16];
	uint16_t 	e_type;
	uint16_t 	e_machine;
	uint16_t 	e_version;
	off_t		e_entry;	
	off_t		e_phoff;	
	off_t		e_shoff;	
	uint32_t    e_flag;
	uint16_t 	e_ehsize;	
	uint16_t    e_phentsize;
	uint16_t    e_phnum;
	uint16_t    e_shentsize;
	uint16_t    e_shnum;
	uint16_t    e_shstrndx;
};

struct Elf_ph_64{
	uint32_t	p_type;
	uint32_t	p_flag;
	off_t 		p_offset;
	uint64_t 	p_vaddr;
	off_t 		p_paddr;
	uint64_t	p_filesz;
	uint64_t	p_memsz;
	off_t		p_align;
};

struct Elf_ph_32{
	uint32_t	p_type;
	uint32_t 	p_offset;
	uint32_t 	p_vaddr;
	uint32_t 	p_paddr;
	uint32_t	p_filesz;
	uint32_t	p_memsz;
	uint32_t	p_flag;
	uint32_t	p_align;
};

struct Elf_sh_64{
	uint32_t	sh_name;
	uint32_t	sh_type;
	uint64_t	sh_flags;
	uint64_t	sh_addr;
	off_t		sh_offset;
	uint64_t	sh_size;
	uint32_t	sh_info;
	uint32_t	sh_link;
	uint64_t	sh_addralign;
	uint64_t	sh_entsize;
};

int inject_instruction_silent(char *target,char *instruction,int inst_size);



#endif
