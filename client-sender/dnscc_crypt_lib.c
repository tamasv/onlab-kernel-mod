/* From nushu 
 *
 */
#include <stdint.h>
#include "../lib/d3des.h"

int cipher;	// 0 - no cipher, 1 - des

void dnscc_crypt_init() {

  cipher = 1;
  char des_key[8+1] = "AAAAAAAA";
  if (!cipher) return;
  deskey (des_key, EN0); 
}

/* encrypt the given dns id */
uint16_t dnscc_crypt (uint16_t id, uint16_t udps, uint16_t udpd, uint32_t ips, uint32_t ipd ) {
  int debug = 1;
  if (!cipher) return id;
  char seed[8];
  strcpy (&seed[0], "PK");
  *((uint16_t*)&seed[2]) = udps ^ udpd;
  *((uint32_t*)&seed[4]) = ips ^ ipd;

  char hash[8];
  des (seed, hash);
  uint16_t key = (*(uint16_t*)hash);
  if(debug){
  	printf("DEBUG \n");
	printf("id: %u \n", id);
	printf("udp source port: %u \n", ntohs(udps));
	printf("udp dest port: %u \n", ntohs(udpd));
	printf("ip source: %u \n", ips);
	printf("ip dest: %u \n", ipd);
	printf("key: %u \n", key);  
  }
  return key ^ id; 
}

