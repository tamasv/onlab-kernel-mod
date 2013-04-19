#include "freadlib.c"
#include "fwritelib.c"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
void main(){

	long pos = 0;
	long size = 0;
	uint8_t r;
	if(open_fread("pelda.txt") == 1){
		printf("Successfully opened file for reading \n");
	}else{
		printf("Error while opening file \n");
		exit(1);
	}
	if(open_fwrite("pelda2.txt") == 1){
		printf("Successfully opened file for writing \n");
	}else{
		printf("Error while opening file \n");
		exit(1);
	}
	size = read_size();
	printf("The file is %d byte long\n",size);
  	while(pos  <= size){
		r = read_byte(pos);
		write_byte(pos,r);
		printf("%d -  %d\n",pos,r);
		pos++;
	}



}
