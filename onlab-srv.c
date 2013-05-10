/*
 * onlab-kernel-srv.c
 *
 * Kernel module for dns covert channel  / server side
 * This module should be loaded on the controlled host, which has the recursive dns
 *
 * Copyright (C) 2013 by Tamas Varga
 *
 */
#undef __KERNEL__
#define __KERNEL__

#undef MODULE
#define MODULE
/* kernel */
#include <linux/module.h> 
#include <linux/kernel.h>
#include <linux/init.h>
#include <net/ip.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/etherdevice.h>
#include <linux/list.h>
#include "dnscc.h"
/* */
/* Def */
#define UDP_HDR_LEN 8
#define DNS_PORT 53
/* statics */
static struct nf_hook_ops nfho_send,nfho_recv;
struct DNS_HEADER {
	uint16_t	query_id;
	uint16_t	flags;
	uint16_t	qdcount;
	uint16_t	ancount;
	uint16_t	nscount;
	uint16_t	arcount;
};
struct DNS_QUERY {
	unsigned char *name;
	struct QUESTION *ques;
};
struct QUESTION
{
	uint16_t qtype;
	uint16_t qclass;
};
/* Struct for identifying a connection in the linked list */
struct conn_data{
	uint32_t ip_addr;
	uint32_t connection_id;
	struct list_head list;
};
struct conn_data conn_list;
/* Connection helpers */
/* Generate an unique connection identifier using the source IP, and the source port
 * and store it in the connection_list 
 */
uint32_t generate_connection_id(uint32_t ip_addr, uint16_t sport){
	struct conn_data* c;
	printk(KERN_DEBUG "[DNSCC] Generating new connection id");
	c = kmalloc(sizeof(*c), GFP_KERNEL);
	c->ip_addr = ip_addr;
	c->connection_id = ip_addr ^ sport;
	INIT_LIST_HEAD(&c->list);
	list_add(&c->list,&conn_list.list);
	return c->connection_id;
}


//TODO:Removeme static const uint16_t port = 53;
unsigned char* read_dns_name(unsigned char* b, unsigned char* buffer, int* count){
	unsigned char *dns_name;
	unsigned int p=0,lo=0;//pointer, for dns_name[p], lo is length octect between labels
	unsigned int l=0,k=0; //used in while
	dns_name = (unsigned char*)kmalloc(256,(GFP_DMA));
	dns_name[0]='\0';

	//read the dns name
	while(*b!=0){
		dns_name[p++] = *b;
		b++;//todo: b++
	}
	dns_name[p] = '\0';
//	printk(KERN_INFO "[DNSCC] DEBUG: dns query name length %u \n",p);
	while(l<p){
		//pick up the first length octet
		lo = (unsigned int)dns_name[l];
//		printk(KERN_INFO "[DNSCC] DEBUG Found length octet %u \n",lo);
		k=0;
		while(k<lo){
			dns_name[l] = dns_name[l+1];
			k++;
			l++;
		}
		dns_name[l]='.';
		l++;
	}
	dns_name[l-1]='\0';//replace last dot
	return dns_name;
}

/*Receiver hook */
static unsigned int dnscc_recv(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in, const struct net_device* out, int (*okfn)(struct sk_buff*)) {
	struct ethhdr* ethh = eth_hdr(skb);
	struct iphdr* iph = ip_hdr(skb);
	struct udphdr* udph = NULL, udpbuff;
	unsigned char *data = NULL,*dns_name;
	struct DNS_HEADER* dns_h = NULL;	/* if it's not udp, then return accept*/
	bool query_bit = false;
	int dnsn_count = 0;
	/* parse dns packet */
	/* check if the packet is valid */
	/* parse IP header */
	if(iph->protocol != IPPROTO_UDP){
		return NF_ACCEPT;
	}
	/* udp header*/
	udph = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(*udph) ,&udpbuff);
	if (!udph){
		return NF_ACCEPT;
	}
	/* We're receiving a question, so dst should be 53 */
	if(ntohs(udph->dest) != DNS_PORT){
		return NF_ACCEPT;
	}
	/* get dns packet */
	data = (unsigned char *) skb_header_pointer (skb, ip_hdrlen(skb)+UDP_HDR_LEN, 0, NULL);
	/* Better way? */
	dns_h = (struct DNS_HEADER*)data;	
	query_bit = (ntohs(dns_h->flags) & 0x8000) >> 15;
	/* DST port == DNS_PORT and dst mac == our mac address */
	if (!query_bit ) {
		dns_name = read_dns_name(&data[sizeof(struct DNS_HEADER)],data,&dnsn_count);
		uint16_t d_id = dnscc_decrypt(ntohs(dns_h->query_id),iph,udph);
		printk(KERN_DEBUG "[DNSCC] Incoming DNS query packet id %u dns-name %s answer = %d \n",ntohs(dns_h->query_id),dns_name,query_bit);
		uint8_t action = dnscc_get_action(d_id);
		/* Check if it's starting packet, or we already have a connection */
		uint32_t connection_id = NULL;
		if(action == 0){ // new connection
			connection_id = generate_connection_id(iph->saddr,ntohs(udph->source));
			printk(KERN_INFO "[DNSCC] New connection id generated %u",connection_id);
		}else if(action == 2){ // find the connection_id
//			connection_id = check_connection_exist(iph->saddr);
		}else if(action == 3){// this is the last segment, remove the connection id
//			connection_id = remove_connection_id(iph->saddr);
		}else{
			printk(KERN_INFO "[DNSCC] Invalid action id: %u", action);
		}
//		printk(KERN_INFO "[DNSCC] Decoded dns id: %u action: %u ",d_id,action);
		kfree(dns_name);
	}

	return NF_ACCEPT;
}


/* Sender hook */
static unsigned int dnscc_send(unsigned int hooknum, struct sk_buff* skb, const struct net_device* on, const struct net_device* out, int (*okfn)(struct sk_buff*)) {
	struct ethhdr* ethh = eth_hdr(skb);
	struct iphdr* iph = ip_hdr(skb);
	struct udphdr* udph = NULL, udpbuff;
	unsigned char *data = NULL,*dns_name;
	struct DNS_HEADER* dns_h = NULL;	/* if it's not udp, then return accept*/
	bool query_bit = false;
	int dnsn_count = 0;
	/* check if the packet is valid */
	/* parse IP header */
	if(iph->protocol != IPPROTO_UDP){
		return NF_ACCEPT;
	}
	/* udp header*/
	udph = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(*udph) ,&udpbuff);
	if (!udph){
		return NF_ACCEPT;
	}
	/* We're sending an asnwer, so src should be 53 */
	if(ntohs(udph->source) != DNS_PORT){
		return NF_ACCEPT;
	}
	/* get dns packet */
	data = (unsigned char *) skb_header_pointer (skb, ip_hdrlen(skb)+UDP_HDR_LEN, 0, NULL);
	/* Better way? */
	dns_h = (struct DNS_HEADER*)data;	
	query_bit = (ntohs(dns_h->flags) & 0x8000) >> 15;
	/* SRC port == DNS_PORT and src mac == our mac address */
	if(query_bit ){
		dns_name = read_dns_name(&data[sizeof(struct DNS_HEADER)],data,&dnsn_count);
		printk(KERN_INFO "[DNSCC] Outgoing DNS answer packet id %u dns-name %s answer = %d \n",ntohs(dns_h->query_id),dns_name,query_bit);
		kfree(dns_name);
		}
	return NF_ACCEPT;
}



/* Load and unload */
static __init int my_init(void){
	/* cipher things */
	int cipher = 1;
	char des_key[8+1]="AAAAAAAA";
	dnscc_crypt_init(cipher,des_key);
	nfho_send.hook 	= dnscc_send; 				//function to call
	nfho_send.hooknum 	= NF_INET_LOCAL_OUT;					//hook num in netfilter TODO: What if the packet is fragmented?
	nfho_send.pf		= NFPROTO_IPV4;				//IPV4
	nfho_send.priority	= NF_IP_PRI_FIRST;			//should be first priority
	nf_register_hook(&nfho_send);				//register netfilter hook
	printk(KERN_INFO "[DNSCC] dnscc_send kernel module loaded\n");
	nfho_recv.hook 	= dnscc_recv; 				//function to call
	nfho_recv.hooknum 	= NF_INET_PRE_ROUTING;					//hook num in netfilter TODO: What if the packet is fragmented?
	nfho_recv.pf		= NFPROTO_IPV4;				//IPV4
	nfho_recv.priority	= NF_IP_PRI_FIRST;			//should be first priority
	nf_register_hook(&nfho_recv);				//register netfilter hook
	printk(KERN_INFO "[DNSCC] dnscc_recv kernel module loaded\n");
	/* Create llist for identifying incoming connections */
	INIT_LIST_HEAD(&conn_list.list);


	return 0;
}

static __exit void my_exit(void){
	nf_unregister_hook(&nfho_send);				//unregister netfilter hook
	printk(KERN_INFO "[DNSCC] dnscc_send kernel module unloaded\n");
	nf_unregister_hook(&nfho_recv);				//unregister netfilter hook
	printk(KERN_INFO "[DNSCC] dnscc_recv kernel module unloaded\n");
	/* Remove all elements from conn_list */
	struct conn_data *c, *tmp;
	list_for_each_entry_safe(c,tmp,&conn_list.list, list){
		printk(KERN_DEBUG "[DNSCC] freeing node %u\n", c->connection_id);
		list_del(&c->list);
		kfree(c);
	}
}

module_init(my_init);
module_exit(my_exit);
