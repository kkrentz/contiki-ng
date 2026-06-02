#include <stddef.h>

/* Minimal mem-routines (no libc available). */
void *memset(void *s, int c, size_t n) {
  unsigned char *p = s;
  while(n--) *p++ = (unsigned char)c;
  return s;
}

void *memcpy(void *d, const void *s, size_t n) {
  unsigned char *dp = d;
  const unsigned char *sp = s;
  while(n--) *dp++ = *sp++;
  return d;
}

void *memmove(void *d, const void *s, size_t n) {
  unsigned char *dp = d;
  const unsigned char *sp = s;
  if(dp < sp) {
    while(n--) *dp++ = *sp++;
  } else {
    dp += n; sp += n;
    while(n--) *--dp = *--sp;
  }
  return d;
}

int memcmp(const void *a, const void *b, size_t n) {
  const unsigned char *ap = a, *bp = b;
  while(n--) {
    if(*ap != *bp) return (int)*ap - (int)*bp;
    ap++; bp++;
  }
  return 0;
}

void SystemInit(void) { }

extern int main(void);

/* Override the spinning Trap_Handler from nrfx startup. Read mcause + mepc
 * so we know what kind of exception fired and at what PC. */
__attribute__((naked,aligned(8)))
void my_trap_handler(void)
{
  __asm__ volatile (
    "csrr  t0, mcause           \n"
    "csrr  t1, mepc             \n"
    "li    t2, 0x2003F000       \n"
    "li    a4, 0xFA110000       \n"
    "andi  t0, t0, 0xFF         \n"
    "or    a4, a4, t0           \n"
    "sw    a4, 0(t2)            \n"   /* counter = 0xFA1100|cause   */
    "sw    t1, 4(t2)            \n"   /* +4      = faulting PC      */
    "1: j  1b                   \n"
  );
}

void _start(void) {
  /* Reroute mtvec from the silent-spin Trap_Handler to ours. */
  __asm__ volatile ("csrw mtvec, %0" :: "r"(my_trap_handler));
  *(volatile unsigned int *)0x2003F000UL = 0xA0000001U;
  main();
  *(volatile unsigned int *)0x2003F000UL = 0xA000FFFFU;
  for(;;);
}

void watchdog_periodic(void) { }
void watchdog_init(void)     { }
void watchdog_start(void)    { }
void watchdog_stop(void)     { }
void watchdog_reboot(void)   { for(;;); }

void _exit(int code) { (void)code; for(;;); }

int _write(int fd, const char *buf, int n) { (void)fd; (void)buf; return n; }
int _read(int fd, char *buf, int n)        { (void)fd; (void)buf; (void)n; return 0; }
int _close(int fd)                          { (void)fd; return 0; }
int _lseek(int fd, int off, int w)          { (void)fd; (void)off; (void)w; return 0; }
int _fstat(int fd, void *st)                { (void)fd; (void)st; return 0; }
int _isatty(int fd)                         { (void)fd; return 1; }
int _kill(int pid, int sig)                 { (void)pid; (void)sig; return -1; }
int _getpid(void)                           { return 1; }
void *_sbrk(int incr)                       { (void)incr; return (void *)-1; }
