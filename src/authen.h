/* authen.h --- 
 */

#ifndef INCLUDED_AUTHEN_H
#define INCLUDED_AUTHEN_H 

#define MAX_PACKET_LEN 600 // 实际传输的 eap 之类的包没有超过过 600
#define EAPOL_ETH_TYPE 0x8e88 // 网络序为大端，本机序为小端

char username[20];
char password[20];
u_char id;
char md5_value[16];

const u_char broad_mac[6] = { 0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03 };
u_char dst_mac[6];
u_char local_mac[6];

void GetMac(char *dev, u_char mac[6]);
void ListDevs(void);
int ReadPacket(u_char *buffer, char *path);

void start(pcap_t *);
void response_id(pcap_t *);
void response_md5(pcap_t *);
void logoff(pcap_t *);

void success(const struct eap_struct *);
void failure();

#endif /* INCLUDED_AUTHEN_H */

