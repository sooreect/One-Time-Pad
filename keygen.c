/**************************************************************************************************
 * Author: Tida Sooreechine
 * Date: 3/14/2017
 * Program: CS344 Program 4 - OTP (One-Time Pad), Part 1 of 5
 * Description: Program creates and output to screen a sequence of random characters of 
 * 	user-specified length. Possible characters include the 26 uppercase letters and space 
 * 	character.
**************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 

int main(int argc, char *argv[]) {
	int keyLength, randNum, minNum, maxNum, i;	

	//check the number of arguments
	if (argc < 2) {
		printf("KEYGEN ERROR: Please specify the number of characters to output.\n");
		exit(1);
	}

	//get the key length from the command line arguments
	keyLength = atoi(argv[1]);		//convert string to integer
	
	srand(time(NULL));		//set the random generator seed	

	//establish lower and upper bounds for random numbers
	minNum = 65 - 1;		//ascii number of A is 65
	maxNum = 90 + 1;		//ascii number of Z is 90

	//generate random numbers and output their ASCII character equivalent
	//if number generated is the lower bound, substitute it with space character's ascii value
	for (i = 0; i < keyLength; i++) {
		randNum = (rand() % (maxNum - minNum)) + minNum;
		if (randNum == minNum) {
			randNum = 32;	//ascii number of space is 32
			printf("%c", randNum); 
		}
		else {
			printf("%c", randNum);
		}
	}
	printf("\n");			//conclude the key sequence with a newline character
	
	return 0;
}


