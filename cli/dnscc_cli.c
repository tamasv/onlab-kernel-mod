#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netlink/netlink.h>
#include <get_file_msg.h>
#include <dnscc_msg.h>
#include <arpa/inet.h>
#define DNSCC_NETLINK_MSG (0x15)


/* main */
main(int argc, char *argv[]){
	struct nl_sock *nl_sk; // netlink socket
	dnscc_msg msg; // test
	int ret;
	bool args_ok = true;
	int command;
	struct in_addr ip;
	char* local_file;
	char* remote_file;
	int len;
	unsigned char *raw_msg;
	struct sockaddr_nl peer;
	/* Check arguments */
	if(argc < 3){
		printf("Usage: dnscc-cli $ip $command \n");
		printf("Valid commands are 1 - get \n");
		args_ok = false;
		return EXIT_FAILURE;
	}
	if(inet_aton(argv[1],&ip) <= 0 ){
		printf("Invalid ip");
		return EXIT_FAILURE;
	}
	command = atoi(argv[2]);
	switch(command){
		case 1: //validate 2 more params
			if(argc == 5){
				get_file_msg data;
				data.ip = ip;
				data.remote_file = argv[3];
				data.local_file = argv[4];
				msg.type = 1;
				msg.data = &data;
				printf("Get filename %s from %s and save as %s \n",data.remote_file,inet_ntoa(data.ip),data.local_file);
			}else{
				printf("Usage: dnscc-cli $ip 1 $remote_file $local_file \n");
				return EXIT_FAILURE;
			}	
			break;
		default:
			args_ok = false;
			printf("No valid command found \n");
			break;
	}

	/* allocate netlink socket */
	if(args_ok){
		printf("Allocating netlink socket ... ");
		nl_sk = nl_socket_alloc();
		if (!nl_sk){
			printf(" error.\n");
		}else{
			printf(" ok.\n");
		}
		/* connect */
		printf("Connecting to dnscc netlink socket ...");
		ret = nl_connect(nl_sk, 31);
		if(ret < 0){
			printf(" error.\n");
			nl_perror(ret,"nl_connect");
			nl_socket_free(nl_sk);
			return EXIT_FAILURE;
		}else{
			printf(" ok.\n");
		}
		/* send the message */
		printf("Sending dnscc message to kernel ...");
		ret = nl_send_simple(nl_sk,DNSCC_NETLINK_MSG,0,&msg,sizeof(msg));
		if(ret < 0){
			printf(" error.\n");
			nl_perror(ret,"nl_send_simple");
			nl_socket_free(nl_sk);
			return EXIT_FAILURE;
		}else{
			printf(" ok. Sent %d bytes\n", ret);
		}
		/* wait for the reply */
		if(( len = nl_recv(nl_sk,&peer,&raw_msg,0)) <= 0){
			fprintf(stderr, "nl_recv(): %s", nl_geterror(len));
			nl_close(nl_sk);
			nl_socket_free(nl_sk);
			return -1;
		}
		printf("Message from kernel ...");
		struct nlmsghdr *h = (struct nlmsghdr*)raw_msg;
		if(nlmsg_ok(h,len)){
			char* data = NLMSG_DATA(h);
			FILE *f = fopen(argv[4], "a+");			
			fprintf(f,"%s",data);
			fclose(f);
		}
		printf(" OK.\n Data saved in %s \n",argv[4]);
		nl_close(nl_sk);
		nl_socket_free(nl_sk);
		return EXIT_SUCCESS;
	}else{
		return EXIT_FAILURE;
	}
}
