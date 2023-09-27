#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static const char *hello_world = "Hello World";

int main()
{
  while (1)
  {
    getchar();
    
    printf("%s\n", hello_world);
  }

  return 0;
}