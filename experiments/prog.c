#include <stdio.h>

//http://www.catonmat.net/blog/simple-ld-preload-tutorial/
int main(void) {
    printf("Calling the fopen() function...\n");

    FILE *fd = fopen("test.txt","r");
    if (!fd) {
        printf("fopen() returned NULL\n");
        return 0;
    }

    printf("fopen() succeeded\n");

    return 0;
}