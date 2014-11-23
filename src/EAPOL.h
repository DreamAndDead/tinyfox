/*
 * EAPOL.h
 * 
 * EAPOL 协议的结构
 */

/*
 * u_char 8byte
 * u_short 16byte
 * u_int 32byte
 */

#ifndef CNS_EAPOL_H_
#define CNS_EAPOL_H_

#define MAC_ADDR_LEN 6

struct eapol_struct {
	/* mac 地址 */
	u_char mac_dst[MAC_ADDR_LEN];
	u_char mac_src[MAC_ADDR_LEN];
	/* eapol 的型别为 0x888e */
	u_short ethe_type;

	/* eapol 版本 */
	u_char eapol_version;

	/* 承载的内容，由其定义字段可更好的理解 */
	u_char eapol_packet_type;
	#define EAP_PACKET 0x00
	#define EAP_START 0x01
	#define EAP_LOGOFF 0x02
	#define EAP_KEY 0x03
	
	/* 没有内容的时候可能为0 */
	u_short eapol_packet_lenth;

	/* 用一个字节点位，使用的时候取址，解析剩下的数据 */
	u_char eapol_packet_body;
};

#endif // CNS_EAPOL_H_
