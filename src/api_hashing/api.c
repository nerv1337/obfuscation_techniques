#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// FNV-1a hash function
unsigned long fnv1a_hash(const char *str) {
  unsigned long hash = 0xcbf29ce484222325UL;
  while (*str) {
    hash ^= (unsigned char)(*str++);
    hash *= 0x100000001b3UL;
  }
  return hash;
}

// Function pointer type for write
typedef ssize_t (*write_function_t)(int fd, const void *buf, size_t count);

// Global variable to store the found function address
void *g_write_function_address = NULL;

// Function to locate the symbol table in the shared object and resolve function
// addresses
void locate_symtable(const char *obj_path, void *base_addr,
                     unsigned long target_hash) {
  int fd = open(obj_path, O_RDONLY);
  if (fd < 0) {
    perror("open");
    return;
  }
  printf("AMOGUS");
  // Map the ELF file into memory
  off_t file_size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET); // Reset file position to beginning

  void *elf_base = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (elf_base == MAP_FAILED) {
    perror("mmap");
    close(fd);
    return;
  }

  // Read ELF header
  ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)elf_base;

  // Read section headers
  ElfW(Shdr) *shdrs = (ElfW(Shdr) *)((char *)elf_base + ehdr->e_shoff);
  const char *shstrtab = (char *)elf_base + shdrs[ehdr->e_shstrndx].sh_offset;

  // Iterate over section headers to find the dynamic symbol table
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdrs[i].sh_type == SHT_DYNSYM) {
      const char *section_name = shstrtab + shdrs[i].sh_name;
      printf("Found symbol table: %s\n", section_name);

      // Read symbol table
      ElfW(Sym) *symtab = (ElfW(Sym) *)((char *)elf_base + shdrs[i].sh_offset);
      const char *strtab =
          (const char *)elf_base + shdrs[shdrs[i].sh_link].sh_offset;
      int num_symbols = shdrs[i].sh_size / shdrs[i].sh_entsize;

      // Iterate each symbol to check for a matching hash
      for (int j = 0; j < num_symbols; j++) {
        const char *sym_name = strtab + symtab[j].st_name;
        if (sym_name[0] != '\0') { // Skip empty symbol names
          unsigned long sym_hash = fnv1a_hash(sym_name);

          // Only print the target function's hash if found
          if (ELF64_ST_TYPE(symtab[j].st_info) == STT_FUNC) {
            if (sym_hash == target_hash) {
              printf("Found target symbol: %s\n", sym_name);
              // Calculate the functions address by adding the base address
              g_write_function_address =
                  (void *)((char *)base_addr + symtab[j].st_value);
              printf("Address of resolved function: %p\n",
                     g_write_function_address);
            }
          }
        }
      }
    }
  }

  munmap(elf_base, file_size);
  close(fd);
}

// Callback function to be called for each shared object
int callback(struct dl_phdr_info *info, size_t size, void *data) {
  unsigned long *target_hash = (unsigned long *)data;

  if (info->dlpi_name && info->dlpi_name[0]) {
    printf("Checking shared object: %s @ %p\n", info->dlpi_name,
           (void *)info->dlpi_addr);
    if (strstr(info->dlpi_name, "libc.so")) {
      locate_symtable(info->dlpi_name, (void *)info->dlpi_addr, *target_hash);
    }
  }
  return 0;
}

int main() {
  unsigned long target_hash = 0xb93a12b0d06caefc;

  printf("Looking for function with hash: 0x%016lx\n", target_hash);

  // Calculate hash for "write" for verification
  printf("FNV-1a hash of \"write\": 0x%016lx\n", fnv1a_hash("write"));

  // First approach: iterate over shared objects and parse ELF symbols
  dl_iterate_phdr(callback, &target_hash);

  // If we found the function in the ELF symbols
  if (g_write_function_address) {
    printf("Function address resolved through ELF parsing: %p\n",
           g_write_function_address);
    write_function_t write_function =
        (write_function_t)g_write_function_address;

    // Use the write function
    const char *message = "Hello from dynamically resolved write function!\n";
    write_function(STDOUT_FILENO, message, strlen(message));
  }

  return 0;
}
