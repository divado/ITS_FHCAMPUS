#include <stdlib.h>
#include <string.h>


int main(int argc, char **argv) {
    char *buf;
    buf = (char *)malloc(sizeof(char) * 32);
    strcpy(buf, argv[1]);
    
    return 0;
}
