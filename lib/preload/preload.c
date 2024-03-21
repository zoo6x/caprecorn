#define _GNU_SOURCE

#include <stdio.h>
#include <link.h>
#include <elf.h> 
#include <string.h> 
#include <dlfcn.h>
#include <unistd.h>

#define nullptr NULL

#define SYS_caprecorn 1357

#define CAPRECORN_SYMBOL 1358

void provide_symbol(void *addr, const char *name)
{
	syscall(SYS_caprecorn, CAPRECORN_SYMBOL, addr, name);
}

void provide_symbols()
{
	printf("In provide_symbols()");

	void *library = dlopen(0, RTLD_NOW | RTLD_GLOBAL);
	struct link_map *map = nullptr;
	int res = dlinfo(library, RTLD_DI_LINKMAP, (void *)&map);
	if (res != 0)
	{
	  printf("dlinfo() failed\n");
	  return;
	}
	printf("link_map = %p\n", map);
	printf("5\n");
	printf("link_prev = %p\n", map->l_prev);
	printf("link_next = %p\n", map->l_next);


	while (map != nullptr)
	{
	    printf("=======================5\n");
	    printf("map = %p\n", map);
	    printf("name = %s\n", map->l_name);
	    if (strcmp(map->l_name, "linux-vdso.so.1") == 0)
	    {
		    map = map->l_next;
		    continue;
	    }

	    Elf64_Sym * symtab = nullptr;
	    char * strtab = nullptr;
	    int symentries = 0;
	    int gotentries = 0;
	    int pltrelsz = 0;
	    int relsz = 0;
	    int relent = 0;
	    int rel_cnt = 0;
	    int rela_plt_cnt = 0;
	    Elf64_Addr got = 0;
	    Elf64_Addr rela_plt = 0;
	    Elf64_Addr rela_dyn = 0;
	    for (ElfW(Dyn) * section = map->l_ld; section->d_tag != DT_NULL; ++section)
	    {
		// printf("Section type = %2ld addr = %016lx\n", section->d_tag, section->d_un.d_ptr);
		if (section->d_tag == DT_SYMTAB)
		{
		    symtab = (Elf64_Sym *)section->d_un.d_ptr;
		    printf("symtab = %p\n", symtab);
		}
		if (section->d_tag == DT_STRTAB)
		{
		    strtab = (char*)section->d_un.d_ptr;
		    printf("strtab = %p\n", strtab);
		}
		if (section->d_tag == DT_SYMENT)
		{
		    symentries = section->d_un.d_val;
		    printf("symentries = %d\n", symentries);
		}
		if (section->d_tag == DT_RELASZ)
		{
		    relsz = section->d_un.d_ptr;
		    printf("relsz = %d\n", relsz);
		}
		if (section->d_tag == DT_RELAENT)
		{
		    relent = section->d_un.d_ptr;
		    printf("relent = %d\n", relent);
		}
		if (section->d_tag == DT_PLTRELSZ)
		{
		    pltrelsz = section->d_un.d_val;
		    rela_plt_cnt = pltrelsz / sizeof(Elf64_Rel);
		    printf("pltrelsz = %d rela_plt_cnt = %d \n", pltrelsz, rela_plt_cnt);
		}
		if (section->d_tag == DT_PLTGOT)
		{
		    got = section->d_un.d_ptr;
		    printf("got = %016lx\n", got);
		}
		if (section->d_tag == DT_JMPREL)
		{
		    rela_plt = section->d_un.d_ptr;
		    printf("rela_plt = %016lx\n", rela_plt);
		}
		if (section->d_tag == DT_RELA)
		{
		    rela_dyn = section->d_un.d_ptr;
		    printf("rela_dyn = %016lx\n", rela_dyn);
		}
	    }
	    if (relent != 0)
	    {
		    rel_cnt = relsz / relent;
		    printf("rel_cnt = %d\n", rel_cnt);
	    } 

	    printf("Rela count = %d :\n", rela_plt_cnt);
	    for (int i = 0; i < rela_plt_cnt; i++)
	    {
		    Elf64_Rela *plt = (Elf64_Rela *)rela_plt + i;
                    if (ELF64_R_TYPE(plt->r_info) == R_X86_64_JUMP_SLOT) 
		    {
			size_t idx = ELF64_R_SYM(plt->r_info);
			size_t str_idx = symtab[idx].st_name;
			//if (idx + 1 > plthook->dynstr_size) {
			//    set_errmsg("too big section header string table index: %" SIZE_T_FMT, idx);
			//    return PLTHOOK_INVALID_FILE_FORMAT;
			//}
			char *name = strtab + str_idx;
			char *addr = (char *)map->l_addr + plt->r_offset;
			printf("%p: %p %2ld %s\n", plt, addr, idx, name);
			provide_symbol(plt, name);
			provide_symbol(addr, name);
		    }
	    }

	    printf("Dyn count = %d :\n", rel_cnt);
	    for (int i = 0; i < rel_cnt; i++)
	    {
		    Elf64_Rela *plt = (Elf64_Rela *)rela_dyn + i;
                    //if (ELF64_R_TYPE(plt->r_info) == R_X86_64_JUMP_SLOT) 
		    {
			size_t idx = ELF64_R_SYM(plt->r_info);
			idx = symtab[idx].st_name;
			//if (idx + 1 > plthook->dynstr_size) {
			//    set_errmsg("too big section header string table index: %" SIZE_T_FMT, idx);
			//    return PLTHOOK_INVALID_FILE_FORMAT;
			//}
			char *name = strtab + idx;
			if (name == NULL || *name == '\0')
				continue;
			char *addr = (char *)map->l_addr + plt->r_offset;
			printf("%p %s\n", addr, name);
			provide_symbol(addr, name);
		    }
	    }

	    printf("Symbols:\n");
	    int size = strtab - (char *)symtab;
	    for (int k = 0; k < size / symentries; ++k)
	    {
		Elf64_Sym *sym = &symtab[k];
		// If sym is function
		//if (ELF64_ST_TYPE(symtab[k].st_info) == STT_FUNC)
		{
		    //str is name of each symbol
		    char *name = &strtab[sym->st_name];
		    Elf64_Addr addr = sym->st_value; 
		    
		    void *raddr = dlsym(library, name);
		    printf("%016p %016lx %s\n", raddr, addr, name);
		    provide_symbol(raddr, name);
		}
	    }

	    map = map->l_next;
    }
}

static void init(int argc, char **argv, char **envp) {
    provide_symbols();
}

static void fini(void) {
    puts(__FUNCTION__);
}


__attribute__((section(".init_array"), used)) static typeof(init) *init_p = init;

