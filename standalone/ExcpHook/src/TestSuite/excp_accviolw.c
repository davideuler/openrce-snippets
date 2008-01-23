#include <stdio.h>

int
main(void)
{
  *(int*)0x88776655 = 1234;

  return 0;
}

