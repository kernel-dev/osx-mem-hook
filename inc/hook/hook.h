#ifndef TRACE_ALL_H
#define TRACE_ALL_H

#include <libproc.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct
{
  pid_t p_id;
  char *p_name;
} process_t;

typedef struct
{
  uint64_t local_addr;
  uint64_t remote_addr;
} memory_scan_t;

uint64_t process_get_baseaddr(uint64_t task);

void hook();

#endif /* trace_all.h */