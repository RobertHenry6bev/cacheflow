//
// Flood the icache with straight line code.
//
#include <assert.h>
#include <inttypes.h>
#include <malloc.h>
#include <pthread.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "params.h"

typedef int(*fooworker)(int);

void *foo_runner(void *vp) {
  fooworker func = *(fooworker*)vp;
  int i = func(1);  // argument is ignored
  (void)i;
  return NULL;
}

uint32_t *get_aligned_code(size_t pagesize, size_t npages) {
  void *memptr = NULL;
  assert(pagesize == 4096);
  int memalign_code = posix_memalign(&memptr, pagesize, npages * pagesize);
  if (memalign_code != 0) {
    perror("posix_align failed");
    exit(1);
  }
  uint64_t low_bits = (((uintptr_t)(memptr)) & (pagesize - 1));
  assert(low_bits == 0);
  if (mprotect(
      memptr,
      npages * pagesize,
      PROT_READ|PROT_WRITE|PROT_EXEC) != 0) {
    perror("mprotect to make writeable and executable");
  }
  return (uint32_t *)(memptr);
}

#define NOP 0xd503201f
#define BRANCH_PLUS_4 0x14000004

uint32_t *fill_aligned_code(uint32_t *code, size_t ninsns) {
  int i = 0;
  pid_t pid = getpid();
  assert(ninsns >= 32);

  //
  // for a loop iteration of 6M times:
  // 6000000 == 6 * 1000 * 1000 == (0x5b<<16) + 0x8d80
  // We'll start with code that was compiled for 6000000,
  // and swap in the bits for "count".
  //
  {
    uint32_t count = 6 * 1000 * 1000;
    uint32_t upper = (count >> 16) & 0xffff;
    uint32_t lower = (count >>  0) & 0xffff;
    uint32_t movw = 0x5291b001;  // movw w1, #0x8d80
    uint32_t movk = 0x72a00b61;  // movk w1, #0x5b, lsl #16 (base)
    uint32_t mask = ((1 << (20-5+1)) - 1) << 5;
    movw = (movw & ~mask) | ((lower << 5) & mask);
    movk = (movk & ~mask) | ((upper << 5) & mask);
    code[i++] = movw;
    code[i++] = movk;
  }

  int Ltop = i;
  while (i % 16 != 0) {
    code[i++] = NOP;
  }
  while (i < ninsns - 20) {
    code[i++] = BRANCH_PLUS_4;
    if (1) {
      code[i++] = 0xffffffff;  // marker
      code[i++] = pid;         // pid
      uint32_t address_self = (uint32_t)(intptr_t)&code[i];  // Take that, you type system!
      code[i++] = address_self;
    } else {
      code[i++] = NOP;
      code[i++] = NOP;
      code[i++] = NOP;
    }
 }

 //
 // Generate loop test and branch back to top for more
 //
 code[i++] = 0x71000421; //  subs w1, w1, #0x1
 {
   int deltai = Ltop - i;
   uint32_t imm_mask = ((1<<(23-5+1)) - 1) << 5;
   uint32_t bne = 0x54effe21; //  b.ne 0xd88 // imm field is 23:5; low 4 bits encode cond
   bne &= ~imm_mask;
   bne |= (deltai << 5) & imm_mask;
   code[i++] = bne;
 }

 code[i++] = 0xd65f03c0; //  ret

 return &code[i];
}

void lock_aligned_code(void *memptr, size_t pagesize, size_t npages) {
  if (mprotect(
      memptr,
      npages * pagesize,
      PROT_READ|PROT_EXEC) != 0) {
    perror("mprotect to make wrieable and executable");
  }
}

#define NTHREAD 4  //  Raspberry Pi 4
int main(int argc, const char **argv) {
  int i;
  fooworker thread_arg[NTHREAD];
  pthread_t *worker_thread = calloc(NTHREAD, sizeof(pthread_t));

  size_t pagesize = getpagesize();
  size_t npages = 16;
  size_t ninsns = (pagesize * npages) / sizeof(uint32_t);

  uint32_t *code_block = get_aligned_code(pagesize, npages);
  fill_aligned_code(code_block, ninsns);
  lock_aligned_code(code_block, pagesize, npages);
  __builtin___clear_cache(code_block, code_block+ninsns);  // builtin for gcc

  fooworker func = (fooworker)code_block;
  if (1) {
    func(1);
    printf("DONE!\n");
  } else {
    for (i = 0; i < NTHREAD; i++) {
      thread_arg[i] = func;
      pthread_create(
        &worker_thread[i],
        NULL,
        foo_runner,
        &thread_arg[i]);
    }
    for (i = 0; i < NTHREAD; i++) {
      pthread_join(worker_thread[i], NULL);
    }
  }
  return 0;
}
