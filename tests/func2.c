#include <stdio.h>

extern void func1();

int main()
{
	printf("start\n");
	func1();
	printf("end\n");
	return 0;
}
