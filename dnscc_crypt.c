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

#include "lib/d3des.h"

int cipher;	// 0 - no cipher, 1 - des

void dnscc_crypt_init(int cipher_mode, char des_key[8]) {
  cipher = cipher_mode;
  if (!cipher) return;
  deskey (des_key, EN0); 
}

/* encrypt the given dns id */
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

/* Decrypt the given dns id */
uint16_t dnscc_decrypt (uint16_t id, struct iphdr* ip, struct udphdr *udp ) {
  int debug = 1;
  if (!cipher) return id;
  char seed[8];
  strcpy (&seed[0], "PK");
  *((uint16_t*)&seed[2]) = udp->source ^ udp->dest;
  *((uint32_t*)&seed[4]) = ip->saddr ^ ip->daddr;

  char hash[8];
  des (seed, hash);

  uint16_t key = (*(uint16_t*)hash);
  if(debug){
        printk( KERN_DEBUG "[DNSCC][DES DEBUG] id: %u \n", id);
        printk( KERN_DEBUG "[DNSCC][DES DEBUG] udp source port: %u \n", ntohs(udp->source));
        printk( KERN_DEBUG "[DNSCC][DES DEBUG] udp dest port: %u \n", ntohs(udp->dest));
        printk( KERN_DEBUG "[DNSCC][DES DEBUG] ip source: %u \n", ip->saddr);
        printk( KERN_DEBUG "[DNSCC][DES DEBUG] ip dest: %u \n", ip->daddr);
        printk( KERN_DEBUG "[DNSCC][DES DEBUG] key: %u \n", key);  
  }

  return key ^ id;

}

/* This function will return the action from the dns id
 * 00 - NOOP
 * 01 - Start data transfer
 * 10 - In data transfer
 * 11 - End data transfer
 */
uint8_t dnscc_get_action(uint16_t id)
{
	uint8_t act;
	uint16_t temp;
	temp = (id & 0xC000 ) >> 14;
	act = (uint8_t) temp;
	return act;
}

/* This will return the decoded packet number
 */
uint8_t dnscc_get_packetno(uint16_t id)
{
	uint8_t pos;
	uint16_t temp;
	temp = (id & 0x3F00) >> 8;
	pos = (uint8_t) temp;
	return pos;
}
/* Return data from decoded dnsid
 */
uint8_t dnscc_get_data(uint16_t id){
	return (uint8_t) id;
}
