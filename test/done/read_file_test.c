#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *input;
    unsigned char buffer[600];
    int size;
    input = fopen("packet.bin", "rb");
    if (input == NULL) {
        fprintf(stderr, "file open error");
        exit(1);
    }

    size = fread(buffer, sizeof(unsigned char), 600, input);
    if (size == 0) {
        fprintf(stderr, "can't read anything");
        exit(1);
    }

    printf("File size: %d\n", size);

    int i;
    for (i = 0; i < size; i++) {
        if (i % 0x10 == 0)
            printf("\n");
        printf("%2.2X ", buffer[i]);
    }

    fclose(input);
    return 0;

}
