#include <stdio.h>

int
main(void)
{
  ((void(*)())"\x8e\xc8")(); // this is mov cs, ax

  return 0;
}

