#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int Fibonacci(int n)
{
   if ( n == 0 )
      return 0;
   else if ( n == 1 )
      return 1;
   else
      return ( Fibonacci(n-1) + Fibonacci(n-2) );
} 

int main()
{
	int pid, return_status;
	int i;

	for (i = 0; i < 0x10; i++)
	{
		pid = fork();
		if (!pid)
		{
			printf("issue fork %d\n", i);
			Fibonacci(10);
			exit(i);
		} else {
			waitpid(pid, &return_status, 0);
			printf("round %d exit with %d\n", i, WEXITSTATUS(return_status));
		}
	}
	getchar();

	return 0;
}