#include <stdio.h>

int main()
{
	unsigned long total = 0;
	unsigned long skip = 0;
	int s,t;
	while(scanf("%d %d",&s,&t)!=EOF)
	{
		printf("%d %d\n",s,t);
		total += (unsigned long)t;
		skip += (unsigned long)s;
	}
	printf("Skip/Total=%lu/%lu=%.2f\n",
		skip,
		total,
		(float)skip/(float)total);
	return 0;
}

