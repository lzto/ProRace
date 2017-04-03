/*
 * loop test
 */
#include <stdio.h>

void work(int x)
{
	int i;
	for(i=0;i<x;i++)
	{
		printf(".");
	}
}

int main(int argc, char** argv)
{
	printf("Begin\n");
	work(atol(argv[1]));
	printf("End\n");
	return 0;
}
