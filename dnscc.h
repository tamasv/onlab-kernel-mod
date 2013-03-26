#ifndef __DNSCC_H_
#define __DNSCC_H_
void dnscc_crypt_init(int cipher_mode, char des_key[8]) ;
uint16_t dnscc_encrypt (uint16_t id, struct iphdr* ip, struct udphdr *udp ) ;
uint16_t dnscc_decrypt (uint16_t id, struct iphdr* ip, struct udphdr *udp ) ;
uint8_t dnscc_get_action(uint16_t id);

#endif
