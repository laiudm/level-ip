#include <pthread.h>
#include <stdio.h>

pthread_cond_t      cond2;

int main(int argc, char **argv)
{
  int                   rc=0;

  printf("Create the all of the default conditions in different ways\n");
  rc = pthread_cond_init(&cond2, NULL);
  printf("pthread_cond_init() %i\n", rc);

  printf("- At this point, the conditions with default attributes\n");
  printf("- Can be used from any threads that want to use them\n");

  printf("Cleanup\n");
  pthread_cond_destroy(&cond2);

  printf("Main completed\n");
  return 0;
}