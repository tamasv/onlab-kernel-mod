/* From nushu 
 *
 */
#define MODULE
#define __KERNEL__

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif


#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/ip.h>

#include "d3des.h"

int cipher;	// 0 - no cipher, 1 - des

void dnscc_crypt_init(int cipher_mode, char des_key[8]) {
  cipher = cipher_mode;
  if (!cipher) return;
  deskey (des_key, EN0); 
}

uint16_t dnscc_encrypt (uint16_t id, struct iphdr* ip, struct udphdr *udp ) {
  if (!cipher) return id;
  char seed[8];
  strcpy (&seed[0], "PK");
  *((uint16_t*)&seed[2]) = udp->source ^ udp->dest;
  *((uint32_t*)&seed[4]) = ip->saddr ^ ip->daddr;

  char hash[8];
  des (seed, hash);

  uint16_t key = (*(uint16_t*)hash);
 
  return key ^ id; 
}


uint16_t dnscc_decrypt (uint16_t id, struct iphdr* ip, struct udphdr *udp ) {
  if (!cipher) return id;
  char seed[8];
  strcpy (&seed[0], "PK");
  *((uint16_t*)&seed[2]) = udp->source ^ udp->dest;
  *((uint32_t*)&seed[4]) = ip->saddr ^ ip->daddr;

  char hash[8];
  des (seed, hash);

  uint16_t key = (*(uint16_t*)hash);
  return key ^ id;

}


