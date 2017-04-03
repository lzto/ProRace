#include <stdio.h>

int main(int argc, char** argv)
{
	int i = 0;
	if(argc>1)
		i = atol(argv[1]);
	if(i)
	{
		printf("hello world!\n");
	}else
	{
		printf("bye world!\n");
	}
	return 0;
}

