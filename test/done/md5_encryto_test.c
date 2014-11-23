/*
 * md5 compute
 *
 */



#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

unsigned char from[17] = {0x28,0xf2,0x19,0xbb,0x19,0xab,0x99,0x82,0x34,0xa8,0x74,0xa0,0x9b,0x56,0xad,0x8b,'\0'};
unsigned char to[17] = {0x49,0x50,0x1a,0xa3,0xd4,0xcd,0xd3,0xb6,0x3c,0x89,0xbd,0x5e,0x15,0xa5,0xb8,0xd2,'\0'};
unsigned char password[16] = "myself";
unsigned char username[11] = "U201117735";

unsigned char data[50] = {'\0'};
unsigned char result[16];

void PrintStr(unsigned char array[16]) {
  unsigned char tmp[3] = { '\0' }, buf[33] = { '\0' };
  int i;
  for (i = 0; i < 16; i++) {
      sprintf(tmp, "%2.2x", array[i]);
      strcat(buf, tmp);
    }
  printf("%s\n", buf);
}

int main(void) {
    printf("dst str:\n");
    PrintStr(to);
    printf("src str:\n");
    PrintStr(from);
    
    data[0] = 0x02;
    memcpy(data + 1, password, 6);
    memcpy(data + 7, from, 0x10);
    printf("cat str:\n");
    printf("%s\n", data);
    printf("cat str len:\n");
    printf("%d\n", strlen(data));
  
    MD5(data, 0x17, result);
    
    printf("the result:\n");
    PrintStr(result);
    
    return 0;
}

