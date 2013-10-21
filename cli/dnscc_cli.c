#include <stdio.h>
#include <stdlib.h>
#include <netlink/netlink.h>

#define DNSCC_NETLINK_MSG (0x10 + 5)


/* main */
main(int argc, char *argv[]){
	struct nl_sock *nl_sk; // netlink socket
	char msg[4] = "test"; // test
	int ret;

	/* allocate netlink socket */
	printf("Allocating netlink socket ... ");
	nl_sk = nl_socket_alloc();
	if (!nl_sk){
		printf(" error. Cant' alllocate netlink socket\n");
	}else{
		printf(" ok.\n");
	}
	/* connect */
	printf("Connecting to dnscc netlink socket ...");
	ret = nl_connect(nl_sk, NETLINK_USERSOCK);
	if(ret < 0){
		printf(" error. Can't connect to dnscc netlink socket\n");
		nl_perror(ret,"nl_connect");
		nl_socket_free(nl_sk);
		return EXIT_FAILURE;
	}else{
		printf(" ok.\n");
	}
	/* send the message */
	printf("Sending dnscc message to kernel ...");
	ret = nl_send_simple(nl_sk,DNSCC_NETLINK_MSG,0,msg,sizeof(msg));
	if(ret < 0){
		printf(" error.Can't send message to dnscc kernel module\n");
		nl_perror(ret,"nl_send_simple");
		nl_socket_free(nl_sk);
		return EXIT_FAILURE;
	}else{
		printf(" ok. Sent %d bytes\n", ret);
	}
	nl_close(nl_sk);
	nl_socket_free(nl_sk);


	return EXIT_SUCCESS;
}
