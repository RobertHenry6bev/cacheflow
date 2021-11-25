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

#include "flooders.c.out"

typedef int(*foorunner)(int);
static foorunner foorunners[] = {
  foo_0x0,
  foo_0x1,
  foo_0x2,
  foo_0x3,
  foo_0x4,
  foo_0x5,
  foo_0x6,
  foo_0x7,
  foo_0x8,
  foo_0x9,
  foo_0xa,
  foo_0xb,
  foo_0xc,
  foo_0xd,
  foo_0xe,
  foo_0xf,
};

void *foo_runner(void *vp) {
  int runner_number = getpid() % 16;
  printf("runner_number=%d\n", runner_number);
  int i = foorunners[runner_number](*(int *)vp);
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
    perror("mprotect");
  }
  return (uint32_t *)(memptr);
}

#define NOP 0xd503201f
#define BRANCH_PLUS_4 0x14000004

uint32_t *fill_aligned_code(uint32_t *code, size_t ninsns) {
   int i = 0;
   pid_t pid = getpid();
   assert(ninsns > 64);
   code[i++] = 0x5291b001;  // movw 1, #0x8d80
   code[i++] = 0x72a00b61;  // movk w1, #0x5b, lsl #16
   int Ltop = i;
   while (i % 16 != 0) {
     code[i++] = NOP;
   }
   while (i < ninsns - 20) {
     code[i++] = BRANCH_PLUS_4;
     code[i++] = 0xffffffff;  // marker
     code[i++] = pid;         // pid
     uint32_t address_self = (uint32_t)(intptr_t)&code[i];  // Take that, you type system!
     code[i++] = address_self;
  }
  code[i++] = 0x71000421; //  subs w1, w1, #0x1
  int deltai = Ltop - i;
  uint32_t imm_mask = ((1<<(23-5+1)) - 1) << 5;
  uint32_t bne = 0x54effe21; //  b.ne 0xd88 <foo_0x0+8>  // TODO FIXME Immediate field is 23:5; low 4 bits encode cond
  bne &= ~imm_mask;
  bne |= (deltai << 5) & imm_mask;
  code[i++] = bne;

  code[i++] = 0xd65f03c0; //  ret

  return &code[i];
}

#define NTHREAD 4  //  Raspberry Pi 4
int main(int argc, const char **argv) {
  int i;
  int thread_arg[NTHREAD];
  pthread_t *worker_thread = calloc(NTHREAD, sizeof(pthread_t));

  size_t pagesize = getpagesize();
  size_t npages = 16;
  size_t ninsns = (pagesize * npages) / sizeof(uint32_t);
  uint32_t *code_block = get_aligned_code(pagesize, npages);
  fill_aligned_code(code_block, ninsns);
  foorunner func = (foorunner)code_block;
  func(1);

  for (i = 0; i < NTHREAD; i++) {
    thread_arg[i] = i;
    pthread_create(
      &worker_thread[i],
      NULL,
      foo_runner,
      &thread_arg[i]);
  }
  // sleep(10);
  for (i = 0; i < NTHREAD; i++) {
    pthread_join(worker_thread[i], NULL);
  }
  return 0;
}
