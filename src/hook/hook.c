#include "hook/hook.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <memory.h>

#include <libproc.h>

#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>

#include <sys/proc_info.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>

//
//  Scans through the provided [start, start + size>
//  bytes of the process's memory and attempts to find a sequence of
//  bytes which match the provided signature.
//
memory_scan_t *scan_memory(task_t wow, vm_address_t start,
                           mach_msg_type_number_t size,
                           unsigned char *signature, int signature_size) {
  memory_scan_t *scan = malloc(sizeof(memory_scan_t));

  mach_vm_address_t buffer = (mach_vm_address_t)malloc(signature_size);
  mach_vm_size_t sz = signature_size;

  for (uint64_t bytes_read = 0; bytes_read <= size; bytes_read++) {
    mach_vm_address_t addr = (start + bytes_read);

    //
    // Read memory from process into buffer of size `signature_size'.
    //
    kern_return_t status = mach_vm_read_overwrite(wow, addr, sz, buffer, &sz);

    if (status != KERN_SUCCESS) {
      continue;
    }

    //
    //  Check if the buffer matches the provided signature.
    //
    if (memcmp((void *)buffer, signature, signature_size) == 0) {
      scan->local_addr = addr;
      scan->remote_addr = (uint64_t)buffer;

      return scan;
    }
  }

  return NULL;
}

uint64_t process_get_baseaddr(uint64_t task) {
  kern_return_t ret;

  mach_vm_size_t vm_size = 0;
  mach_vm_address_t base_addr = 0;
  natural_t depth = 0;
  struct vm_region_submap_info_64 info;
  mach_msg_type_number_t region_info_cnt = sizeof(info);

  //
  //  Attempt to obtain relative base address of the process.
  //
  ret =
      mach_vm_region_recurse(task, &base_addr, &vm_size, &depth,
                             (vm_region_recurse_info_t)&info, &region_info_cnt);

  if (ret != KERN_SUCCESS) {
    return 0;
  }

  return base_addr;
}

//
//  This function is necessary due to
//  `mach_vm_protect' not liking misaligned
//  size values.
//
int align_size(size_t size) {
  int align = sizeof(long);
  int aligned_size = (size / align) * align + align;
  return aligned_size;
}

void hook() {
  pid_t *pid_list;

  //
  //  Fetch IDs of all running processes.
  //
  int n_pids = proc_listallpids(NULL, 0);

  if (n_pids <= 0) {
    return;
  }

  pid_list = malloc(sizeof(pid_t) * n_pids);

  n_pids = proc_listallpids(pid_list, sizeof(pid_t) * n_pids);

  process_t *process = malloc(sizeof(process_t));

  for (int i = 0; i < n_pids; i++) {
    struct proc_bsdinfo proc;

    proc_pidinfo(pid_list[i], PROC_PIDTBSDINFO, 0, &proc,
                 PROC_PIDTBSDINFO_SIZE);

    if (strcmp(proc.pbi_name, "dummy") == 0) {
      process->p_id = pid_list[i];
      process->p_name = proc.pbi_name;

      break;
    }
  }

  if (process->p_id <= 0) {
    return;
  }

  printf("FOUND DUMMY WITH PROCESS NAME '%s' AND PID %d\n", process->p_name,
         process->p_id);

  mach_port_t task = 0;

  //
  //  Attempt to obtain a task port for the process.
  //
  kern_return_t status = task_for_pid(mach_task_self(), process->p_id, &task);

  if (status != KERN_SUCCESS) {
    printf("ERROR - %d\n", status);
    exit(1);
  }

  printf("TASK: %d\n", task);

  task_basic_info_data_t info;
  mach_msg_type_number_t infoCount = TASK_BASIC_INFO_COUNT;

  //
  //  Attempt to obtain information about
  //  the process, such as the size of its
  //  virtual address space.
  //
  if (task_info(task, TASK_BASIC_INFO, (task_info_t)&info, &infoCount) !=
      KERN_SUCCESS) {
    return;
  }

  uint64_t base_addr = process_get_baseaddr(task);

  uint64_t memory_size = info.virtual_size;

  //
  //  In the `dummy' process, we know that
  //  the string "Hello World" is located
  //  somewhere in its address space.
  //
  int sig_size = 11;
  unsigned char signature[11] = "Hello World";

  //
  //  Attempt to obtain the remote address,
  //  as well as the relative address,
  //  of the string "Hello World".
  //
  memory_scan_t *scan =
      scan_memory(task, base_addr, memory_size, signature, sig_size);

  char *ptr = (char *)scan->remote_addr;
  uint64_t local = scan->local_addr;

  printf("%s\n", ptr);
  printf("Local = %llX\n", local);

  vm_size_t _size;
  vm_region_basic_info_data_64_t reg_info;
  mach_msg_type_number_t reg_info_count = VM_REGION_BASIC_INFO_COUNT_64;
  mach_port_t obj_name;

  //
  //  Attemp to obtain information about
  //  the process's memory region.
  //
  //  We need this to revert the memory
  //  protection of the memory region later on.
  //
  kern_return_t kr =
      mach_vm_region(task, &base_addr, &_size, VM_REGION_BASIC_INFO_64,
                     (vm_region_info_t)&reg_info, &reg_info_count, &obj_name);

  if (kr != KERN_SUCCESS) {
    printf("Failed to obtain memory region info!\n");
    exit(1);
  }

  unsigned char new_data[] = "All your code are belong to us!";
  vm_size_t vm_size = align_size(strlen(new_data));

  //
  //  Attempt to temporarily change the memory
  //  protection of the memory region.
  //
  kr = mach_vm_protect(task, (vm_address_t)scan->local_addr, vm_size, 0,
                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

  if (kr != KERN_SUCCESS) {
    printf("Failed to vm_protect\n");
    exit(1);
  }

  kr = mach_vm_write(task, (vm_address_t)scan->local_addr,
                     (vm_offset_t)new_data, vm_size);

  if (kr != KERN_SUCCESS) {
    printf("Failed to vm_write\n");
    exit(1);
  }

  //
  //  Revert the memory protection.
  //
  kr = mach_vm_protect(task, (vm_address_t)scan->local_addr, vm_size, 0,
                       reg_info.protection);

  if (kr != KERN_SUCCESS) {
    printf("Failed to revert memory!\n");
    exit(1);
  }
}