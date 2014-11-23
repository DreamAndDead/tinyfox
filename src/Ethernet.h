
#ifndef CNS_ETHERNET_H_
#define CNS_ETHERNET_H_

struct ethernet_struct {
	/* mac 地址 */
	u_char mac_dst[MAC_ADDR_LEN];
	u_char mac_src[MAC_ADDR_LEN];
	/* eapol 的型别为 0x888e */
	u_short ethe_type;
};

#endif // CNS_ETHERNET_H_
