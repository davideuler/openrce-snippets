#include "Math.h"


int __declspec(noinline) Math::square(int val)
{

	return val * val;
}

int doSomething(int val)
{
	Math* x = new Math();
	int r = x->square(val);
	/*delete x;*/
	return r;
}