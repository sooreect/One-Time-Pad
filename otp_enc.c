/**************************************************************************************************
 * Author: Tida Sooreechine
 * Date: 3/14/2017
 * Program: CS344 Program 4 - OTP (One-Time Pad), Part 3 of 5
 * Description: Program takes preexisting plaintext and key files in the current working directory
 * 	as input and validate the contents before transferring them to the encrypting daemon. Program
 * 	receives the ciphertext back and outputs result to screen. 
**************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <fcntl.h>

int main(int argc, char *argv[])
{
	int plainFD, keyFD, socketFD, portNumber, plainSize, keySize, totalChars, i;
	int charsReceived, charsSent, sendPosition;
	char buffer[1000], plainCharArray[999999], keyCharArray[999999], cipherCharArray[999999];
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;

	//check usage and number of arguments
	if (argc < 4) {
		fprintf(stderr, "OTP_ENC USAGE: %s plaintext key port\n", argv[0]); 
		exit(1); 
	} 

	//open plaintext file for reading
	plainFD = open(argv[1], O_RDONLY);
	if (plainFD < 0) {
		fprintf(stderr, "OTP_ENC ERROR: Cannot open %s.\n", argv[1]);
		exit(1);
	}

	//open key file for reading
	keyFD = open(argv[2], O_RDONLY);
	if (keyFD < 0) {
		fprintf(stderr, "OTP_ENC ERROR: Cannot open %s.\n", argv[2]);
		exit(1);
	}
	
	//copy plaintext file to buffer and validate the characters
	memset(plainCharArray, '\0', sizeof(plainCharArray));	//clean out the buffer before usage
	read(plainFD, plainCharArray, sizeof(plainCharArray));	//read from file to buffer
	plainCharArray[strcspn(plainCharArray, "\n")] = '\0';	//truncate the trailing newline character
	plainSize = strlen(plainCharArray);	//get plaintext character count
	for (i = 0; i < plainSize; i++) {
		if (((plainCharArray[i] < 65) && (plainCharArray[i] != 32)) || (plainCharArray[i] > 90)){
			fprintf(stderr, "OTP_ENC ERROR: Input contains bad characters.\n");
			exit(1);
		}
	}
	close(plainFD);	//close file descriptor
	
	//copy key file to buffer and validate the characters
	memset(keyCharArray, '\0', sizeof(keyCharArray));	//clean out the buffer before usage	
	read(keyFD, keyCharArray, sizeof(keyCharArray));	//read from file to buffer
	keyCharArray[strcspn(keyCharArray, "\n")] = '\0';	//truncate the trailing newline character
	keySize = strlen(keyCharArray);	//get key character count
	for (i = 0; i < keySize; i++) {
		if (((keyCharArray[i] < 65) && (keyCharArray[i] != 32)) || (keyCharArray[i] > 90)){
			fprintf(stderr, "OTP_ENC ERROR: Input contains bad characters.\n");
			exit(1);
		}
	}
	close(keyFD);	//close file descriptor

	//verify that key has more characters than plaintext does
	if (keySize < plainSize) {
		fprintf(stderr, "OTP_ENC ERROR: Key '%s' is too short.\n", argv[2]);
		exit(1);
	}

	//set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress));		//clear out the address struct
	serverAddress.sin_family = AF_INET;	//create a network-capable socket
	portNumber = atoi(argv[3]);	//get the port number, convert to an integer from a string
	serverAddress.sin_port = htons(portNumber);	//store the port number in network byte order
	serverHostInfo = gethostbyname("localhost");	//convert the machine name into a special form of address
	if (serverHostInfo == NULL) {
		fprintf(stderr, "OTP_ENC ERROR: No such host.\n");
		exit(1); 
	}
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); //copy in the address

	//set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); //create the socket using TCP protocol
	if (socketFD < 0) {
		fprintf(stderr, "OTP_ENC ERROR: Cannot open socket.\n");
		exit(1);
	}

	//connect to server by connecting socket to address
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
		fprintf(stderr, "OTP_ENC ERROR: Cannot connect to server.\n");
		exit(2);
	}

	//receive acknowledgement from server and verify that it is otp_enc_d and not otp_dec_d
	memset(buffer, '\0', sizeof(buffer));	//clear out the buffer
	charsReceived = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
	if (charsReceived < 0) {
		fprintf(stderr, "OTP_ENC ERROR: Cannot read from socket.\n");
		exit(1);
	}
	if (strcmp("Expecto Patronum!", buffer) != 0) {
		fprintf(stderr, "OTP_ENC ERROR: Wrong communication channel. Terminating!\n");
		exit(1);
	}

	//alert the server the size of plaintext file
	memset(buffer, '\0', sizeof(buffer));	//clear out the buffer
	sprintf(buffer, "%d", plainSize);	//convert plaintext size from integer to string
	charsSent = send(socketFD, buffer, strlen(buffer), 0);	//write to the server
	if (charsSent < 0) {
		fprintf(stderr, "OTP_ENC ERROR: Cannot write to socket.\n");
		exit(1);
	}

	//get receipt from server
	memset(buffer, '\0', sizeof(buffer));	//clear out the buffer
	charsReceived = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
	if (charsReceived < 0) {
		fprintf(stderr, "OTP_ENC ERROR: Cannot read from socket.\n");
		exit(1);
	}
	
	//send plaintext file contents to server
	//send the message piece by piece if the plaintext file size is bigger than the buffer size
	sendPosition = 0;
	while (plainSize > 0) {
		memset(buffer, '\0', sizeof(buffer));	//clear out the buffer

		//copy plain character to buffer
		if (plainSize > sizeof(buffer)) 
			memcpy(buffer, &plainCharArray[sendPosition], sizeof(buffer) - 1);
		else 
			memcpy(buffer, &plainCharArray[sendPosition], plainSize);
		
		//write to the server
		charsSent = send(socketFD, buffer, strlen(buffer), 0);	
		if (charsSent < 0) {
			fprintf(stderr, "OTP_ENC ERROR: Cannot write to socket.\n");
			exit(1);
		}

		plainSize -= charsSent;
		sendPosition += charsSent;	
	}

	//get receipt from server
	memset(buffer, '\0', sizeof(buffer));	//clear out the buffer
	charsReceived = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
	if (charsReceived < 0) {
		fprintf(stderr, "OTP_ENC ERROR: Cannot read from socket.\n");
		exit(1);
	}
	
	//alert the server the size of key file
	memset(buffer, '\0', sizeof(buffer));	//clear out the buffer
	sprintf(buffer, "%d", keySize);	//convert key size from integer to string
	charsSent = send(socketFD, buffer, strlen(buffer), 0);	//write to the server
	if (charsSent < 0) {
		fprintf(stderr, "OTP_ENC ERROR: Cannot write to socket.\n");
		exit(1);
	}

	//get receipt from server
	memset(buffer, '\0', sizeof(buffer));	//clear out the buffer
	charsReceived = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
	if (charsReceived < 0) {
		fprintf(stderr, "OTP_ENC ERROR: Cannot read from socket.\n");
		exit(1);
	}

	//send key file contents to server
	//send the message piece by piece if the key file size is bigger than the buffer size
	sendPosition = 0;
	while (keySize > 0) {
		memset(buffer, '\0', sizeof(buffer));	//clear out the buffer
	
		//copy key characters to the buffer
		if (keySize > sizeof(buffer)) 
			memcpy(buffer, &keyCharArray[sendPosition], sizeof(buffer) - 1);
		else 
			memcpy(buffer, &keyCharArray[sendPosition], keySize);

		//write to the server
		charsSent = send(socketFD, buffer, strlen(buffer), 0);	
		if (charsSent < 0) {
			fprintf(stderr, "OTP_ENC ERROR: Cannot write to socket.\n");
			exit(1);
		}

		keySize -= charsSent;
		sendPosition += charsSent;	
	}

	//get ciphertext characters back from server
	//receive the message in chunks at a time if the ciphertext characters is bigger than buffer size
	totalChars = 0;
	plainSize = strlen(plainCharArray);	//cipherSize should equal plainSize
	memset(cipherCharArray, '\0', sizeof(cipherCharArray));   //clear out char array for storing ciphertext characters 
	while (totalChars < plainSize) { //continue while total chars received is less than expected number
		memset(buffer, '\0', sizeof(buffer));   //clear out the buffer
		charsReceived = recv(socketFD, buffer, sizeof(buffer) - 1, 0);   //get message
		if (charsReceived < 0) {
			fprintf(stderr, "OTP_ENC_D ERROR: Cannot read from socket.\n");
			exit(1);
		}
		strncat(cipherCharArray, buffer, sizeof(buffer) - 1);
		totalChars += charsReceived;
	}
	printf("%s\n", cipherCharArray);
	
	close(socketFD); // Close the socket


	return 0;
}
