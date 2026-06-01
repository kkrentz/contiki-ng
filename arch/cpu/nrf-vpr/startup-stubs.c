#include <stddef.h>

void SystemInit(void) { }

extern int main(void);
void _start(void) { main(); for(;;); }

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
