/* 
 * getopt() test
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern char * optarg;
extern int optind, opterr, optopt;

int main(int argc, char ** argv) {
    char * username;
    char * password;
    char * usage = "usage: ........\n";

    int opt;

    while((opt = getopt(argc, argv, "u:p:h")) != -1) {
        switch (opt) {
            case 'u':
                username = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'h':
                printf("%s", usage);
                break;
            default:
                fprintf(stderr, "the usage is .....\n");
                exit(1);
        }
    }

    printf("username: %s, password: %s\n", username, password);
    return 0;
}
