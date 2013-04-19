#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
FILE * inFile;
/* This function will open the given file, and reset the counters */
int open_fread(char * fname){
	inFile = fopen(fname,"rb");
	if (inFile==NULL) {
		return 0;
	}
	return 1;
}

/* This will return a byte from the file 
 * long p - read a byte, starting from this pos
 *
 */
uint8_t read_byte(long p){
	uint8_t ret;
	fseek (inFile, sizeof(uint8_t) * p, SEEK_SET); // seek from the start
	fread(&ret,sizeof(uint8_t),1,inFile);
	return ret;
}

/* The size of the file, in 8 bit blocks
 */
long read_size(){
	long ret;
	fseek(inFile, 0, SEEK_END);
	ret = ftell (inFile);
	return ret;
}

int close_fread(){
	fclose(inFile);
}
