/* authen.h --- 
 */

#ifndef INCLUDED_AUTHEN_H
#define INCLUDED_AUTHEN_H 

#define MAX_PACKET_LEN 600 // 实际传输的 eap 之类的包没有超过过 600
#define EAPOL_ETH_TYPE 0x8e88 // 网络序为大端，本机序为小端

#include "EAP.h"
#include "EAPOL.h"

extern char username[20];
extern char password[20];
extern u_char id;
extern char md5_value[16];

extern char dev[20];

extern const u_char broad_mac[6];
extern u_char dst_mac[6];
extern u_char local_mac[6];

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

