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
/* */
/* Def */
#define UDP_HDR_LEN 8
#define DNS_PORT 53
/* statics */
static struct nf_hook_ops nfho;
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

/* Hook */
static unsigned int dnscc_func(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in, const struct net_device* out, int (*okfn)(struct sk_buff*)) {
	struct ethhdr* ethh = eth_hdr(skb);
	struct iphdr* iph = ip_hdr(skb);
	struct udphdr* udph, udpbuff;
	unsigned char *data,*dns_name;
	struct DNS_HEADER* dns_h = NULL;	/* if it's not udp, then return accept*/
	int stop=0;
	if(iph->protocol != IPPROTO_UDP){
		return NF_ACCEPT;
	}
	/* udp header*/
	udph = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(*udph) ,&udpbuff);
	if (!udph){
		return NF_ACCEPT;
	}
	if (ntohs(udph->dest) == DNS_PORT){
		printk(KERN_INFO "Dest MAC=%x:%x:%x:%x:%x:%x\n",ethh->h_dest[0],ethh->h_dest[1],ethh->h_dest[2],ethh->h_dest[3],ethh->h_dest[4],ethh->h_dest[5]);
		printk(KERN_INFO "SKB dev MAC=%x:%x:%x:%x:%x:%x\n",skb->dev->dev_addr[0],skb->dev->dev_addr[1],skb->dev->dev_addr[2],skb->dev->dev_addr[3],skb->dev->dev_addr[4],skb->dev->dev_addr[5]);

	}

	/* DST port == DNS_PORT and dst mac == our mac address */
	if (ntohs(udph->dest) == DNS_PORT && ether_addr_equal_64bits(skb->dev->dev_addr,ethh->h_dest) ) {
		data = (unsigned char *) skb_header_pointer (skb, ip_hdrlen(skb)+UDP_HDR_LEN, 0, NULL);
		/* Better way? */
		dns_h = (struct DNS_HEADER*)data;
		/* If first bit is 0, then it's a question */
		bool f_bit = (dns_h->flags & 0x8000) >> 15;
		if(!f_bit){
			dns_name = read_dns_name(&data[sizeof(struct DNS_HEADER)],data,&stop);
			printk(KERN_INFO "[DNSCC] Incoming DNS question packet iph-len: %d data-len %u id %u dns-name %s answer = %d \n",ip_hdrlen(skb),skb->len - ip_hdrlen(skb)-UDP_HDR_LEN,ntohs(dns_h->query_id),dns_name,f_bit);
			kfree(dns_name);
		}
	}
	/* SRC port == DNS_PORT and src mac == our mac address */
	if(ntohs(udph->source) == DNS_PORT ){
		data = (unsigned char *) skb_header_pointer (skb, ip_hdrlen(skb)+UDP_HDR_LEN, 0, NULL);
		/* Better way? */
		dns_h = (struct DNS_HEADER*)data;
		/* If the first bit is 1, then it's an aswer */
		//bool f_bit = (dns_h->flags & 0x8000) >> 15;
		bool f_bit = 1;
		//if(f_bit){
			dns_name = read_dns_name(&data[sizeof(struct DNS_HEADER)],data,&stop);
			printk(KERN_INFO "[DNSCC] Outgoing DNS answer packet iph-len: %d data-len %u id %u dns-name %s answer = %d \n",ip_hdrlen(skb),skb->len - ip_hdrlen(skb)-UDP_HDR_LEN,ntohs(dns_h->query_id),dns_name,f_bit);
		//	printk(KERN_INFO "Source MAC=%x:%x:%x:%x:%x:%x\n",ethh->h_source[0],ethh->h_source[1],ethh->h_source[2],ethh->h_source[3],ethh->h_source[4],ethh->h_source[5]);
		//	printk(KERN_INFO "SKB dev MAC=%x:%x:%x:%x:%x:%x\n",skb->dev->dev_addr[0],skb->dev->dev_addr[1],skb->dev->dev_addr[2],skb->dev->dev_addr[3],skb->dev->dev_addr[4],skb->dev->dev_addr[5]);
			kfree(dns_name);
		//}
	}
	return NF_ACCEPT;
}



/* Load and unload */
static __init int my_init(void){
	nfho.hook 	= dnscc_func; 				//function to call
	nfho.hooknum 	= NF_INET_LOCAL_OUT;					//hook num in netfilter TODO: What if the packet is fragmented?
	nfho.pf		= NFPROTO_IPV4;				//IPV4
	nfho.priority	= NF_IP_PRI_FIRST;			//should be first priority
	nf_register_hook(&nfho);				//register netfilter hook
	printk(KERN_INFO "[DNSCC]Kernel module loaded\n");
	return 0;
}

static __exit void my_exit(void){
	nf_unregister_hook(&nfho);				//unregister netfilter hook
	printk(KERN_INFO "[DNSCC]Kernel module unloaded\n");
}

module_init(my_init);
module_exit(my_exit);
