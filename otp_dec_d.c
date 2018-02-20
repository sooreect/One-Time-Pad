/**************************************************************************************************
 * Author: Tida Sooreechine
 * Date: 3/16/2017
 * Program: CS344 Program 4 - OTP (One-Time Pad), Part 4 of 5
 * Description: Program functions as a daemon that decrypts messages. It receives sets of
 * 	ciphertext and key characters from a client program and outputs plaintext messages back to the
 * 	client.
**************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char *argv[])
{
	int listenSocketFD, establishedConnectionFD, portNumber, spawnPid, ch, kch, i;
	int charsReceived, charsSent, totalChars, plainCount, keyCount, cipherCount, sendPosition;
	char buffer[1000], plainChars[999999], keyChars[999999], cipherChars[999999];
	struct sockaddr_in serverAddress, clientAddress;
	socklen_t sizeOfClientInfo;

	//check usage and number of arguments
	if (argc < 2) {
		fprintf(stderr, "OTP_DEC_D USAGE: %s port\n", argv[0]);
		exit(1);
	}

	//set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress));	//clear out the address struct
	serverAddress.sin_family = AF_INET;	//create a network-capable socket
	portNumber = atoi(argv[1]);	//get the port number, convert to an integer from a string
	serverAddress.sin_port = htons(portNumber);	//store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; //any address is allowed for connection to this process

	//set up the listening socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); //create the socket using TCP protocol
	if (listenSocketFD < 0) {
		fprintf(stderr, "OTP_DEC_D ERROR: Cannot open socket.\n");
		exit(1);
	}

	//connect socket to port to enable listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
		fprintf(stderr, "OTP_DEC_D ERROR: Cannot bind socket.\n");
		exit(1); 
	}
	listen(listenSocketFD, 5); //flip the socket on - it can now receive up to 5 connections

	while(1) {	//infinite loop
		//accept a connection from client, blocking if one is not available until one connects
		sizeOfClientInfo = sizeof(clientAddress); //get the size of the address for the client that will connect
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); //accept
		if (establishedConnectionFD < 0) {
			fprintf(stderr, "OTP_DEC_D ERROR: Cannot accept client connection.\n");
			exit(1);
		}
		
		spawnPid = fork();	//create a new process after connection has been established
		if (spawnPid < 0) {
			fprintf(stderr, "OTP_DEC_D ERROR: Cannot fork.\n"); 
			exit(1);
		} 
		else if (spawnPid == 0) {	
			//child process
			close(listenSocketFD); //close the listening socket

			//send acknowledgement to client, confirming that it is otp_dec and not otp_enc
			charsSent = send(establishedConnectionFD, "Avada Kedavra!", 14, 0);	
			if (charsSent < 0) 
				fprintf(stderr, "OTP_DEC_D ERROR: Cannot write to socket.\n"); 

			//get ciphertext characters count
			memset(buffer, '\0', sizeof(buffer));	//clear out the buffer
			charsReceived = recv(establishedConnectionFD, buffer, sizeof(buffer) - 1, 0);	//get message
			if (charsReceived < 0) 
				fprintf(stderr, "OTP_DEC_D ERROR: Cannot read from socket.\n");
			cipherCount = atoi(buffer);

			//send receipt to client
			charsSent = send(establishedConnectionFD, "Received.", 9, 0);	
			if (charsSent < 0) 
				fprintf(stderr, "OTP_DEC_D ERROR: Cannot write to socket.\n"); 
	
			//get ciphertext file content			
			//receive the message broken up chunks if the ciphertext file is larger than buffer size
			totalChars = 0;
			memset(cipherChars, '\0', sizeof(cipherChars));	//clear out char array for storing ciphertext chars 
			while (totalChars < cipherCount) {	//continue while total characters received is less than expected count
				memset(buffer, '\0', sizeof(buffer));	//clear out the buffer
				charsReceived = recv(establishedConnectionFD, buffer, sizeof(buffer) - 1, 0);	//get message
				if (charsReceived < 0) 
					fprintf(stderr, "OTP_DEC_D ERROR: Cannot read from socket.\n");
				strncat(cipherChars, buffer, sizeof(buffer) - 1);		
				totalChars += charsReceived;
			}

			//send receipt to client
			charsSent = send(establishedConnectionFD, "Received.", 9, 0);	
			if (charsSent < 0) 
				fprintf(stderr, "OTP_DEC_D ERROR: Cannot write to socket.\n"); 

			//get key characters count
			memset(buffer, '\0', sizeof(buffer));	//clear out the buffer
			charsReceived = recv(establishedConnectionFD, buffer, sizeof(buffer) - 1, 0);	//get message
			if (charsReceived < 0) 
				fprintf(stderr, "OTP_DEC_D ERROR: Cannot read from socket.\n");
			keyCount = atoi(buffer);
		
			//send receipt to client
			charsSent = send(establishedConnectionFD, "Received.", 9, 0);	
			if (charsSent < 0) 
				fprintf(stderr, "OTP_DEC_D ERROR: Cannot write to socket.\n");
	
			//get key file content			
			//receive the message broken up chunks if the key file is larger than buffer size
			totalChars = 0;
			memset(keyChars, '\0', sizeof(keyChars));	//clear out char array for storing key characters 
			while (totalChars < keyCount) {	//continue while total chars received is less than expected number
				memset(buffer, '\0', sizeof(buffer));	//clear out the buffer
				charsReceived = recv(establishedConnectionFD, buffer, sizeof(buffer) - 1, 0);	//get message
				if (charsReceived < 0) {
					fprintf(stderr, "OTP_ENC_D ERROR: Cannot read from socket.\n");
				}
				strncat(keyChars, buffer, sizeof(buffer) - 1);		
				totalChars += charsReceived;
			}

			//decrypt ciphertext characters with the key
			memset(plainChars, '\0', sizeof(plainChars));	//clear out char array for storing decrypted text 
			for (i = 0; i < cipherCount; i++) {
				//reassign each plaintext character a number within range 0-26 based on their ascii value
				if (cipherChars[i] == 32)	//if ciphertext char is a space  
					ch = 0;
				else
					ch = cipherChars[i] - 64;	//if ciphertext char is A-Z
				
				//reassign each key character a number within range 0-26 based on their ascii value
				if (keyChars[i] == 32)	//if key char is a space  
					kch = 0;
				else
					kch = keyChars[i] - 64;	//if key char is A-Z

				//decryption
				ch = ch - kch;
				if (ch < 0)
					ch += 27;
				ch += 64;
				if (ch == 64) 
					ch = 32;
				
				//copy the encrypted character to the cipherText 
				plainChars[i] = ch;
			}
			plainCount = strlen(plainChars);

			//send plaintext characters back to client
			//send the message piece by piece if the plaintext character count is bigger than the buffer size
			sendPosition = 0;
			while (plainCount > 0) {
				memset(buffer, '\0', sizeof(buffer));   //clear out the buffer

				//copy plaintext characters to buffer
				if (plainCount > sizeof(buffer))
	             	memcpy(buffer, &plainChars[sendPosition], sizeof(buffer) - 1);	
				else
					memcpy(buffer, &plainChars[sendPosition], cipherCount);

				//write to the server
				charsSent = send(establishedConnectionFD, buffer, strlen(buffer), 0);  
				if (charsSent < 0) 
					fprintf(stderr, "OTP_DEC_D ERROR: Cannot write to socket.\n");

				cipherCount -= charsSent;
				sendPosition += charsSent;
			}

			exit(0); 
		}
		else {
			//parent process
			close(establishedConnectionFD); //close the existing socket which is connected to the client
		}
	}

	return 0; 
}
