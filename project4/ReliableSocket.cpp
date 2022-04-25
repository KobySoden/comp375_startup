/*
 * File: ReliableSocket.cpp
 *
 * Reliable data transport (RDT) library implementation.
 *
 * Author(s):
 *
 */

// C++ library includes
#include <iostream>
#include <string.h>

// OS specific includes
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ReliableSocket.h"
#include "rdt_time.h"

using std::cerr;
using std::cout;

/*
 * NOTE: Function header comments shouldn't go in this file: they should be put
 * in the ReliableSocket header file.
 */

ReliableSocket::ReliableSocket() {
	this->sequence_number = 0;
	this->expected_sequence_number = 0;
	this->estimated_rtt = 100;
	this->dev_rtt = 10;

	// TODO: If you create new fields in your class, they should be
	// initialized here.

	this->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (this->sock_fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	this->state = INIT;
}
void PrintSegment(char * segment, int size){
	for(int i =0; i < size; i++) cerr << std::to_string(segment[i]);
	cerr << "\n";
}
void ReliableSocket::accept_connection(int port_num) {
	if (this->state != INIT) {
		cerr << "Cannot call accept on used socket\n";
		exit(EXIT_FAILURE);
	}
	
	// Bind specified port num using our local IPv4 address.
	// This allows remote hosts to connect to a specific port.
	struct sockaddr_in addr; 
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port_num);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(this->sock_fd, (struct sockaddr*)&addr, sizeof(addr)) ) {
		perror("bind");
	}

	// Wait for a segment to come from a remote host
	char segment[MAX_SEG_SIZE];
	memset(segment, 0, MAX_SEG_SIZE);

	struct sockaddr_in fromaddr;
	unsigned int addrlen = sizeof(fromaddr);
	int recv_count = recvfrom(this->sock_fd, segment, MAX_SEG_SIZE, 0, 
								(struct sockaddr*)&fromaddr, &addrlen);		
	if (recv_count < 0) {
		perror("accept recvfrom");
		exit(EXIT_FAILURE);
	}

	/*
	 * UDP isn't connection-oriented, but calling connect here allows us to
	 * remember the remote host (stored in fromaddr).
	 * This means we can then use send and recv instead of the more complex
	 * sendto and recvfrom.
	 */
	if (connect(this->sock_fd, (struct sockaddr*)&fromaddr, addrlen)) {
		perror("accept connect");
		exit(EXIT_FAILURE);
	}

	// Check that segment was the right type of message, namely a RDT_CONN
	// message to indicate that the remote host wants to start a new
	// connection with us.
	RDTHeader* hdr = (RDTHeader*)segment;
	if (hdr->type != RDT_CONN) {
		cerr << "ERROR: Didn't get the expected RDT_CONN type.\n";
		exit(EXIT_FAILURE);
	}
	//assume header is valid
	this->state = SYN_RECIEVED;

	//increment syn by one and set it as the ack number
	uint32_t ack = ntohl(hdr->sequence_number) + 1;
	hdr->ack_number = htonl(ack);

	//hardcode syn number for now
	hdr->sequence_number = htonl(75);
	//send new header back to host
	if (send(this->sock_fd, hdr, sizeof(RDTHeader), 0) < 0) {
         perror("syn/ack");
		 exit(EXIT_FAILURE);
	}
	this->state = SYN_SENT;

	//wait for response 
	recv_count = recvfrom(this->sock_fd, segment, MAX_SEG_SIZE, 0, 
								(struct sockaddr*)&fromaddr, &addrlen);		
	if (recv_count < 0) {
		perror("accept recvfrom");
		exit(EXIT_FAILURE);
	}
		
	//new ack should be old syn+1
	if (ntohl(hdr->ack_number) != 75 + 1){
		cerr << "Ack Number is wrong\n";
		//shouldnt exit here we should send the syn again or something like
		//that
		exit(EXIT_FAILURE);	
	}

	//Debug Stuff
	cerr <<"Reciever\n";
	for(int i = 0; i < MAX_SEG_SIZE; i++){
		cerr << std::to_string(segment[i]);
	}
	cerr <<"\n";

	this->state = ESTABLISHED;
	cerr << "INFO: Connection ESTABLISHED\n";
	
	//might want to change this to start at our syn numbers from before 
	this->expected_sequence_number = 0;
}

void ReliableSocket::connect_to_remote(char *hostname, int port_num) {
	if (this->state != INIT) {
		cerr << "Cannot call connect_to_remote on used socket\n";
		return;
	}
	
	// set up IPv4 address info with given hostname and port number
	struct sockaddr_in addr; 
	addr.sin_family = AF_INET; 	// use IPv4
	addr.sin_addr.s_addr = inet_addr(hostname);
	addr.sin_port = htons(port_num); 

	/*
	 * UDP isn't connection-oriented, but calling connect here allows us to
	 * remember the remote host (stored in fromaddr).
	 * This means we can then use send and recv instead of the more complex
	 * sendto and recvfrom.
	 */
	if(connect(this->sock_fd, (struct sockaddr*)&addr, sizeof(addr))) {
		perror("connect");
	}

	// Send an RDT_CONN message to remote host to initiate an RDT connection.
	char segment[sizeof(RDTHeader)];
	RDTHeader* hdr = (RDTHeader*)segment;
	
	//hardcoded syn num for now
	long syncNum = 55;

	hdr->ack_number = htonl(0);
	hdr->sequence_number = htonl(syncNum);
	hdr->type = RDT_CONN;
	if (send(this->sock_fd, segment, sizeof(RDTHeader), 0) < 0) {
		perror("conn1 send");
	}
	this->state = SYN_SENT;

	
	// Wait for a syn/ack from  a remote host
	memset(segment, 0, sizeof(RDTHeader));

	unsigned int addrlen = sizeof(addr);
	int recv_count = recvfrom(this->sock_fd, segment, sizeof(RDTHeader), 0, 
								(struct sockaddr*)&addr, &addrlen);		
	if (recv_count < 0) {
		perror("accept recvfrom");
		exit(EXIT_FAILURE);
	}

	//compare recieved syn with sent syn+1
	if (ntohl(hdr->ack_number) != syncNum+1){
		//add new state here maybe
		cerr << "Syn/Ack not recieved correctly retry\n";
		//shouldnt exit here we should retry sending syn or something
		exit(EXIT_FAILURE);
	}
	this->state = SYN_RECIEVED;

	//increment syn by 1 and send it back as ack
	hdr->ack_number = htonl(ntohl(hdr->sequence_number) + 1);
	if (send(this->sock_fd, segment, sizeof(RDTHeader), 0) < 0) {
		perror("conn2 send");
	}

	//Debug Stuff
	//cerr <<"Sender\n";
	//for(int i = 0; i < sizeof(RDTHeader); i++){
	//	cerr << std::to_string(segment[i]);
	//}
	//cerr <<"\n";

	this->state = ESTABLISHED;
	cerr << "INFO: Connection ESTABLISHED\n";
}


// You should not modify this function in any way.
uint32_t ReliableSocket::get_estimated_rtt() {
	return this->estimated_rtt;
}

// You shouldn't need to modify this function in any way.
void ReliableSocket::set_timeout_length(uint32_t timeout_length_ms) {
	cerr << "INFO: Setting timeout to " << timeout_length_ms << " ms\n";
	struct timeval timeout;
	msec_to_timeval(timeout_length_ms, &timeout);

	if (setsockopt(this->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
					sizeof(struct timeval)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
}

void ReliableSocket::send_data(const void *data, int length) {
	if (this->state != ESTABLISHED) {
		cerr << "INFO: Cannot send: Connection not established.\n";
		return;
	}

 	// Create the segment, which contains a header followed by the data.
	char segment[MAX_SEG_SIZE];

	// Fill in the header
	RDTHeader *hdr = (RDTHeader*)segment;
	hdr->sequence_number = htonl(sequence_number);
	hdr->ack_number = htonl(0);
	hdr->type = RDT_DATA;

	// Copy the user-supplied data to the spot right past the 
	// 	header (i.e. hdr+1).
	memcpy(hdr+1, data, length);
	
	//start timer for rtt here	
	if (send(this->sock_fd, segment, sizeof(RDTHeader)+length, 0) < 0) {
		perror("send_data send");
		exit(EXIT_FAILURE);
	}

	// TODO: This assumes a reliable network. You'll need to add code that
	// waits for an acknowledgment of the data you just sent, and keeps
	// resending until that ack comes.
	// Utilize the set_timeout_length function to make sure you timeout after
	// a certain amount of waiting (so you can try sending again).
	
	//wait for response on timeout resend packet	
	int recv_count = recv(this->sock_fd, segment, MAX_SEG_SIZE, 0);
	if (recv_count < 0) {
		perror("receive_data recv");
		exit(EXIT_FAILURE);
	}
	//end timer for rtt here

//	PrintSegment(segment, sizeof(RDTHeader));
	
	//check that recieved packet is type ACK and that we recieved the right
	//ack number might need to add another conditional for seq #
	if(hdr->type == RDT_ACK && ntohl(hdr->ack_number) == (long)length){
		cerr << "we have an ACK!\n";
		sequence_number = ntohl(hdr->sequence_number) + 1;
		cerr << std::to_string(sequence_number) << "\n";
	}
	//retry send
	else send_data(data, length); 
}


int ReliableSocket::receive_data(char buffer[MAX_DATA_SIZE]) {
	if (this->state != ESTABLISHED) {
		cerr << "INFO: Cannot receive: Connection not established.\n";
		return 0;
	}

	char received_segment[MAX_SEG_SIZE];
	memset(received_segment, 0, MAX_SEG_SIZE);

	// Set up pointers to both the header (hdr) and data (data) portions of
	// the received segment.
	RDTHeader* hdr = (RDTHeader*)received_segment;	
	void *data = (void*)(received_segment + sizeof(RDTHeader));

	int recv_count = recv(this->sock_fd, received_segment, MAX_SEG_SIZE, 0);
	if (recv_count < 0) {
		perror("receive_data recv");
		exit(EXIT_FAILURE);
	}
	
	//cloes connection sent
	if(hdr->type == RDT_CLOSE){
		cerr << "RDT_CLOSE Recieved\n";
		//this->state = 
		return 0;
	}

	//check for data transmission
	if(hdr->type != RDT_DATA){
		cerr << "Unexpected RDT Type Recieved\n";
		//ask for a retransmission?
		return 0;
	}
	//debug stuff
	cerr << "expecting seq #: " << std::to_string(expected_sequence_number) << "\n";
	
	//printout recieved packet
	cerr << "INFO: Received segment. " 
		 << "seq_num = "<< ntohl(hdr->sequence_number) << ", "
		 << "ack_num = "<< ntohl(hdr->ack_number) << ", "
		 << ", type = " << hdr->type << "\n";
	
	//wrong sequence #
	if(ntohl(hdr->sequence_number) != expected_sequence_number){
		cerr << "Wrong sequence number\n";
		//if sequence number recieved is old ack the packet
		if (ntohl(hdr->sequence_number) < expected_sequence_number){
			//set ack number to data recieved
			hdr->ack_number = htonl(recv_count - sizeof(RDTHeader));
			
			//

			cerr << "Acking old packet\n";
		}
		//return for now
		cerr << "Wrong sequence number\n";
		return 0;
	}

	//we got the expected sequence #
	else{
		//ack the amount of data received
		hdr->ack_number = htonl(recv_count - sizeof(RDTHeader));
		
		//update sequence numbers
		sequence_number += ntohl(hdr->ack_number);
		expected_sequence_number = sequence_number + 1;	//add 1 for unique seq	
		hdr->sequence_number = htonl(sequence_number);
	
		//set header type to ack to send back
		hdr->type = RDT_ACK;
	
		//send ack
		if (send(this->sock_fd, received_segment, sizeof(RDTHeader), 0) < 0) {
			perror("send ack");
			exit(EXIT_FAILURE);
		}
	
		//copy data to buffer
		int recv_data_size = recv_count - sizeof(RDTHeader);
		memcpy(buffer, data, recv_data_size);

		return recv_data_size;
	}
}

void ReliableSocket::close_connection() {
	// Construct a RDT_CLOSE message to indicate to the remote host that we
	// want to end this connection.
	char segment[sizeof(RDTHeader)];
	RDTHeader* hdr = (RDTHeader*)segment;

	hdr->sequence_number = sequence_number;
	hdr->ack_number = htonl(0);
	hdr->type = RDT_CLOSE;

	if (send(this->sock_fd, segment, sizeof(RDTHeader), 0) < 0) {
		perror("close send");
	}

	//wait for response should be a close message


	// TODO: As with creating a connection, you need to add some reliability
	// into closing the connection to make sure both sides know that the
	// connection has been closed.

	if (close(this->sock_fd) < 0) {
		perror("close_connection close");
	}
}
