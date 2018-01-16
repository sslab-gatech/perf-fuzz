#include <stdio.h>
#include <stdlib.h>

void f(int argc, char *argv[], char *envp[])
{
	int x, y;

    x = atoi(argv[1]);
    y = atoi(argv[2]); 

	if (x > 3)
		if (y < 2) {
			printf("1");
		} else {
			printf("2");
		}
	else
		printf("3");

    printf("waiting...");
    fflush(stdout);

    getchar();
}

int main(int argc, char *argv[], char *envp[])
{
	f(argc, argv, envp);
}
