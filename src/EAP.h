/*
 * EAP.h
 *
 * EAP 协议数据包的结构
 *
 */

/*
 * u_char 8byte
 * u_short 16byte
 * u_int 32byte
 */

#ifndef CNS_EAP_H_
#define CNS_EAP_H_

struct eap_struct {
	/* eap 数据包的类型 */
	u_char eap_code;
	#define CODE_REQUEST 0x01
	#define CODE_RESPONSE 0x02
	#define CODE_SUCCESS 0x03
	#define CODE_FAILURE 0x04
	#define CODE_INITIATE 0x05
	#define CODE_FINISH 0X06

	/* identifier 用来确定 request 与 response 的对应关系 */
	u_char eap_identifier;
	
	/* 整个包的长度，包括前面的 code 与 identifier 部分 */
	u_short eap_lenth;

	/* 如果eap_lenth == 0，下面定义的变量不可用 */
	/* request 与 response 的类型，才会使用 type */
	u_char eap_type;
	/* 只根据需要定义这两处类型 */
	#define TYPE_IDENTITY 0x01
	#define TYPE_MD5_CHALLENGE 0x04
	/* 用一个字节占位，使用的时候 &，并根据长度获得剩下的数据 */
	u_char eap_type_data;
};

#endif // CNS_EAP_H_
