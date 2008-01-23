#define _WIN32_WINNT 0x505
#include <cstdio>
#include <windows.h>

using namespace std;

LONG CALLBACK MyHandler(
 PEXCEPTION_POINTERS ExceptionInfo
)
{
  putchar('.');
  return EXCEPTION_CONTINUE_EXECUTION;
}

DWORD WINAPI MyThread(PVOID a)
{
  while(1)
  {
    *(int*)0 = 0; 
  }

  return 0;
}

int
main(void)
{
  int i;
  puts("Press ctrl-c to stop");
  AddVectoredExceptionHandler(1, MyHandler);
 

  for(i = 0; i < 10; i++)
  {
    CreateThread(NULL, 0, MyThread, 0, 0, NULL);
  }

  while(1)
  {
  }
 
  return 0;
}

