#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#include <stdio.h>
#include <tchar.h>
#include "Math.h"

int _tmain(int argc, _TCHAR* argv[])
{
	printf("%d",doSomething(23));
	return 0;
}

