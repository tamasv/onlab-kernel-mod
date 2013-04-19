#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
FILE * outFile;
/* This function will open the given file, and reset the counters */
int open_fwrite(char * fname){
	outFile = fopen(fname,"wb");
	if (inFile==NULL) {
		return 0;
	}
	return 1;
}

/* This will write a byte 
 * long p - write a byte, starting from this pos
 * uint8_t data - the data
 */
uint8_t write_byte(long p, uint8_t data){
	fseek (outFile, sizeof(uint8_t) * p, SEEK_SET); // seek from the start
	fwrite(&data,sizeof(uint8_t),1,outFile);
	return 1;
}

int close_fwrite(){
	fclose(outFile);
}

