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

//absolute value for devrtt
#include <cmath>

#include "ReliableSocket.h"
#include "rdt_time.h"

using std::cerr;
using std::cout;

//RDT Send states
#define SEND_DATA		0
#define WAIT_FOR_ACK	1

//RDT Receive states
#define WAIT_FOR_DATA 	0
#define VERIFY_DATA 	1
#define SEND_ACK 		2
#define SEND_OLD_ACK	3

//Close states (sender)
#define SEND_CLOSE		0
//#define WAIT_FOR_ACK	1 //this is defined above already
#define ACK_ACK			2
#define CLOSE			3

//close (receiver)
#define RECEIVE_CLOSE	0
#define ACK_CLOSE		1
#define RECEIVE_ACK_ACK 2

/*
 * NOTE: Function header comments shouldn't go in this file: they should be put
 * in the ReliableSocket header file.
 */

ReliableSocket::ReliableSocket() {
	this->sequence_number = 0;
	this->expected_sequence_number = 0;
	this->estimated_rtt = 10;
	this->dev_rtt = 10;
	this->timeout = 100;
	this->receiver_rtt = 0;

	this->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (this->sock_fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	set_timeout_length((uint32_t)timeout);

	this->state = INIT;
}

void ReliableSocket::had_timeout(){
	//sets a cap on the timeout value
	if(this->timeout < this->estimated_rtt * 5){
		this->timeout = 1.5 * this->timeout;
	}
	cerr << "TIMEOUT!\n"; 
	set_timeout_length((uint32_t)this->timeout);
}

void ReliableSocket::EWMA(int rtt){ 
	cerr << "rtt: " << rtt << "\n";
	//divide by 2 to fix innaccuracy
	//rtt = rtt/2;
	
	this->estimated_rtt = uint32_t((.7 * this->estimated_rtt) + (.3 *
	rtt));
	//calculate new dev_rtt value
	this->dev_rtt = uint32_t((.75*this->dev_rtt) + (.25*std::abs(rtt -
	this->estimated_rtt))); 
	
	//set timeout value 
	this->timeout = this->estimated_rtt + (this->dev_rtt);
	set_timeout_length((uint32_t)this->timeout);
	cerr << "EWMA RTT: " << this->estimated_rtt << " DEV_RTT: " <<
	this->dev_rtt << "\n";
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
	if (bind(this->sock_fd, (struct sockaddr*)&addr, sizeof(addr)) ) {
		perror("bind");
	}

	// Wait for a segment to come from a remote host
	char segment[MAX_SEG_SIZE];
	memset(segment, 0, MAX_SEG_SIZE);
	RDTHeader* hdr = (RDTHeader*)segment;

	//declaring variables used in state machine
	struct sockaddr_in fromaddr;
	unsigned int addrlen = sizeof(fromaddr);
	int recv_count = 0;	
	uint32_t ack = 0;
	int rtt = 0;
	
	while(1){	
		switch(this->state){
			case INIT:
				//receive response
				memset(segment, 0, MAX_SEG_SIZE);
				recv_count = recvfrom(this->sock_fd, segment,
				sizeof(RDTHeader), 0, (struct sockaddr*)&fromaddr, &addrlen);		
				if(recv_count < 0){
					cerr << "Did not receive syn\n";
					had_timeout();
				}else if(connect(this->sock_fd, (struct sockaddr*)&fromaddr,
				addrlen)){
					cerr << "Cannot conenct sockets\n";
				}else{
					if(hdr->type != RDT_CONN){
						cerr << "ERROR: Didn't get the expected RDT_CONN type.\n";
					}else{	
						
					//	cerr << "INFO: received segment. " 
		 			//	<< "seq_num = "<< ntohl(hdr->sequence_number) << ", "
		 			//	<< "ack_num = "<< ntohl(hdr->ack_number) << ", "
		 			//	<< "type = " << hdr->type << " length: " 
					//	<< ntohl(hdr->length) << "\n";
						
						this->state = SYN_RECEIVED;
					}	
				}
				break;

			case SYN_RECEIVED:	
				
				//increment syn by one and set it as the ack number
				ack = ntohl(hdr->sequence_number) + 1;
				hdr->ack_number = htonl(ack);
				
				//hardcode syn number for now
				hdr->sequence_number = htonl(75);
					
				//cerr << "INFO: sent  segment. " 
		 		//<< "seq_num = "<< ntohl(hdr->sequence_number) << ", "
		 		//<< "ack_num = "<< ntohl(hdr->ack_number) << ", "
		 		//<< "type = " << hdr->type << " length: " 
				//<< ntohl(hdr->length) << "\n";
				

				//send new header back to host
				if (send(this->sock_fd, hdr, sizeof(RDTHeader), 0) < 0) {
         			cerr << "couldn't send  syn/ack\n";
				}else {
					//start rtt timer
					rtt = current_msec();
					this->state = SYN_SENT;
				}
				break;

			case SYN_SENT:

				memset(segment, 0, sizeof(RDTHeader));
				
				recv_count = recv(this->sock_fd, segment,
				sizeof(RDTHeader), 0);		
				if(recv_count < 0){
					cerr << "could not recieve ack for syn/ack\n";
					this->state = SYN_RECEIVED;
				}else if(hdr->type == RDT_DATA) {
					cerr << "missed the ack but sender is sending data\n";
					this->state = ESTABLISHED;
				}
				else if(ntohl(hdr->ack_number) == 76){
					cerr << "Received proper ack: "<< ntohl(hdr->ack_number)<< "\n";
					//stop rtt timer
					rtt = current_msec() - rtt;
					this->estimated_rtt = rtt;
					this->dev_rtt = rtt;
					this->state = ESTABLISHED;
				}
				else if(hdr->type == RDT_CONN){
					cerr << "Received first syn message\n";
					this->state = SYN_RECEIVED;
				}
					
				else{
					cerr << "Something weird happened\n";
					this->state = INIT;
				}


				//cerr << "INFO: received segment. " 
		 		//<< "seq_num = "<< ntohl(hdr->sequence_number) << ", "
		 		//<< "ack_num = "<< ntohl(hdr->ack_number) << ", "
		 		//<< "type = " << hdr->type << "\n"; 
				break;

			case ESTABLISHED:
				cerr << "INFO: Connection ESTABLISHED\n";
				return;
			default:
				break;
		}
	}	


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
		cerr << "cannot connect socket\n";
	}
	
	char segment[sizeof(RDTHeader)];
	RDTHeader* hdr = (RDTHeader*)segment;
	//hardcoded syn num for now
	long syncNum = 55;
	int recv_count = 0;
	int rtt = 0;

	while(1){
		
		switch(this->state){
			case INIT:
				// Send an RDT_CONN message to remote host to initiate an RDT connection.
				memset(segment, 0, sizeof(RDTHeader));
				hdr->ack_number = htonl(0);
				hdr->sequence_number = htonl(syncNum);
				hdr->type = RDT_CONN;
				//debug
	//			cerr << "INFO: sending segment. " 
	//	 		<< "seq_num = "<< ntohl(hdr->sequence_number) << ", "
	//	 		<< "ack_num = "<< ntohl(hdr->ack_number) << ", "
	//	 		<< ", type = " << hdr->type << " length: " 
	//			<< ntohl(hdr->length) << "\n";
				
				if (send(this->sock_fd, segment, sizeof(RDTHeader), 0) < 0) {
					cerr << "cannot send syn\n";
				}else {
					//start rtt timer
					rtt = current_msec();
					this->state = SYN_SENT;
				}
				break;

			case SYN_SENT:		
				// Wait for a syn/ack from  a remote host
				memset(segment, 0, sizeof(RDTHeader));
				
				recv_count = recv(this->sock_fd, segment, sizeof(RDTHeader),0);			 
				if (recv_count < 0) {
					cerr << "Did not receive SYN/ACK from remote host\n";
					this->state = INIT;
				}else if(hdr->type != RDT_CONN || ntohl(hdr->ack_number) !=
				syncNum +1){
					cerr << "wrong sequence number received or wrong type of packet\n";
					this->state = INIT;
				}else {
					//end rtt time
					rtt = current_msec() - rtt;
					this->estimated_rtt = rtt;
					this->dev_rtt = rtt;
					this->state = SYN_RECEIVED;
				}
	//			cerr << "INFO: received segment. " 
	//	 		<< "seq_num = "<< ntohl(hdr->sequence_number) << ", "
	//	 		<< "ack_num = "<< ntohl(hdr->ack_number) << ", "
	//	 		<< "type = " << hdr->type << " length: " 
	//	 		<< ntohl(hdr->length) << "\n";
				break;

			case SYN_RECEIVED:
				//increment syn by 1 and send it back as ack
				hdr->ack_number = htonl(ntohl(hdr->sequence_number) + 1);
				
	//			cerr << "INFO: sent segment. " 
	//	 		<< "seq_num = "<< ntohl(hdr->sequence_number) << ", "
	//	 		<< "ack_num = "<< ntohl(hdr->ack_number) << ", "
	//	 		<< "type = " << hdr->type << " length: " 
	//	 		<< ntohl(hdr->length) << "\n";
				
				if (send(this->sock_fd, segment, sizeof(RDTHeader), 0) < 0) {
					cerr << "Failed to respond to SYN\n";
				}else this->state = ESTABLISHED;
				break;

			case ESTABLISHED: 
				cerr << "INFO: CONNECTION ESTABLISHED\n";
				return;

			default:
				break;
		}
	}
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
	//call RDT SEND
	return RDTSend(data, length);
}
void ReliableSocket::RDTSend(const void *data, int length){
	
 	// Create the segment, which contains a header followed by the data.
	char segment[MAX_SEG_SIZE];

	RDTHeader *hdr = (RDTHeader*)segment;
	
	//receive count for ack values
	int recv_count = 0;
	
	//variable for rtt
	int rtt = 0;

	//state machine for send data
	int state = SEND_DATA;
	set_timeout_length(this->timeout);
	while(1){
	//	cerr << "Current State: " << state << "\n";
		switch(state){
			case SEND_DATA:
				//try to send data
				// Fill in the header
				hdr->sequence_number = htonl(sequence_number);
				hdr->ack_number = htonl(0);
				hdr->type = RDT_DATA;
				hdr->length = htonl(length);
				memcpy(hdr+1, data, length);
				
				if(send(this->sock_fd, segment, sizeof(RDTHeader)+length, 0)<0){
					cerr << "couldn't send data\n";
				}else{
						
					//get current time for rtt
					rtt = current_msec();
					//cerr << "INFO: Sent segment. " 
		 			//<< "seq_num = "<< ntohl(hdr->sequence_number) << ", "
		 			//<< "ack_num = "<< ntohl(hdr->ack_number) << ", "
		 			//<< "type = " << hdr->type << " length: " 
					//<< ntohl(hdr->length) << "\n";

					state = WAIT_FOR_ACK;
				}
				break;
		
			case WAIT_FOR_ACK:
				//wait for response
				recv_count = recv(this->sock_fd, segment, sizeof(RDTHeader), 0);
				rtt = current_msec() - rtt;
				if(recv_count < 0){
					cerr << "Did not receive an ack\n";
					had_timeout();
				}else if(hdr->type != RDT_ACK){
					cerr << "Received Something but it wasn't an ack\n";
				}
				else if(ntohl(hdr->sequence_number) == sequence_number){
					cerr << "We got an ack for the right segment\n";
					sequence_number++;
					//adjust rtt value
					EWMA(rtt);
					cerr << "RTT: " << rtt << "\n";
					return;
				}
				state = SEND_DATA;
				break;
		}
	}
}

int ReliableSocket::receive_data(char buffer[MAX_DATA_SIZE]) {
	if (this->state != ESTABLISHED) {
		cerr << "INFO: Cannot receive: Connection not established.\n";
		return 0;
	}
	
	return RDTReceive(buffer);
}

int ReliableSocket::RDTReceive(char buffer[MAX_DATA_SIZE]){
	
	char received_segment[MAX_SEG_SIZE];
	memset(received_segment, 0, MAX_SEG_SIZE);
	
	//set up pointers to header and data	
	RDTHeader* hdr = (RDTHeader*)received_segment;	
	void *data = (void*)(received_segment + sizeof(RDTHeader));

	int recv_count = 0;
	int	recv_data_size = 0;
	
	set_timeout_length(this->timeout);

	//state machine for receving data
	int state = WAIT_FOR_DATA;
	while(1){
	//	cerr << "Current State: " <<  state << "\n";
		switch(state){
			case WAIT_FOR_DATA:	
				
				//receive data	
				recv_count = recv(this->sock_fd, received_segment, MAX_SEG_SIZE, 0);
				if (recv_count < 0) {
					//cerr << "Nothing Received\n";
					had_timeout();
				}
				else{	
					//end timer for rtt this comes from last segment 
					if(this->receiver_rtt != 0){ 
						EWMA(current_msec() - this->receiver_rtt);
						this->receiver_rtt = 0;
					}else EWMA(this->estimated_rtt);
						
	//				cerr << "INFO: Received segment. " 
	//	 			<< "seq_num = "<< ntohl(hdr->sequence_number) << ", "
	//	 			<< "ack_num = "<< ntohl(hdr->ack_number) << ", "
	//	 			<< "type = " << hdr->type << " length: " 
	//				<< ntohl(hdr->length) << "\n";
					
					state = VERIFY_DATA;
				}
				break;
			
			case VERIFY_DATA:
				
				if(hdr->type == RDT_CLOSE){
					this->state = RECEIVED_CLOSE;
					return 0;
				}
				else if(hdr->type == RDT_DATA){
					//corrupted packet
					if(ntohl(hdr->length) != recv_count - sizeof(RDTHeader)){
						this->receiver_rtt = 0;
						state = WAIT_FOR_DATA;
					}
				//sequence number matches
				else if(ntohl(hdr->sequence_number) == expected_sequence_number){
						//increment sequence numbers
						sequence_number++;
						expected_sequence_number++;
						
						//save data to buffer
						recv_data_size = recv_count - sizeof(RDTHeader);
						memcpy(buffer, data, recv_data_size);
						//send ack
						state = SEND_ACK;
					}
					//old sequence number
					else if(ntohl(hdr->sequence_number) <
						expected_sequence_number){
						
						this->receiver_rtt = 0;
						state = SEND_OLD_ACK;
					}	
					else{
						//cerr << "INFO: Data could not be verified\n";
						this->receiver_rtt = 0;
						state = WAIT_FOR_DATA;
					}
				}
				else {
					this->receiver_rtt = 0;
					state = WAIT_FOR_DATA;
				}
				break;
			
			case SEND_ACK:
				hdr->type = RDT_ACK;
				
				if(send(this->sock_fd, received_segment, sizeof(RDTHeader), 0) < 0) {
					cerr << "Cant Send ACK\n";
				}

				//TODO add condition here if we cant send an ack	
				this->receiver_rtt = current_msec();
				
				return recv_data_size;
				break;
			
			case SEND_OLD_ACK:
				hdr->type = RDT_ACK;

				if(send(this->sock_fd, received_segment, sizeof(RDTHeader), 0) < 0) {
					cerr << "Cant Send old ACK\n";
				}
				state = WAIT_FOR_DATA;
				break;
		}
	}
}
void ReliableSocket::close_connection() {
	if(this->state == CLOSED){
		cerr << "Coneection already closed\n";
		return;
	}

	cerr << "State entering close_connection() = " << this->state << "\n";

	//call seperate function for receiver
	if(this->state == RECEIVED_CLOSE)
		return receiver_close(); 

	char segment[sizeof(RDTHeader)];
	RDTHeader* hdr = (RDTHeader*)segment;

	this->expected_sequence_number = this->sequence_number + 1;

	int rtt = 0;
	int state = SEND_CLOSE;

	//state machine for closing
	while(1){
		switch(state){
			case SEND_CLOSE:
				//fill header
				hdr->sequence_number = htonl(this->sequence_number);
				hdr->ack_number = htonl(0);
				hdr->type = RDT_CLOSE;
			
				//send close message	
				if (send(this->sock_fd, segment, sizeof(RDTHeader), 0) < 0) {
					cerr << "Couldn't send close message\n";
				}
				else{
					rtt = current_msec();
					cerr << "Sent Close Packet\n";
					state = WAIT_FOR_ACK;
				}
			
			break;
		
			case WAIT_FOR_ACK:
				//clear buffer
				memset(segment, 0, sizeof(RDTHeader));
		
				if(recv(this->sock_fd, segment, sizeof(RDTHeader), 0) < 0){
					cerr << "Did not receive ack\n";
					had_timeout();
					state = SEND_CLOSE;
				}else if(hdr->type == RDT_CLOSE){
					cerr << "Received ack for close message\n";
				
					if(ntohl(hdr->sequence_number) ==
						this->expected_sequence_number){
						//end rtt timer 
						rtt = current_msec() - rtt;
						EWMA(rtt);

						//increment sequence numbers
						sequence_number++;
						expected_sequence_number++;
						state = ACK_ACK;	
					}

				}else{
					cerr << "received wrong kind of message\n";
				}
			break;
		
			case ACK_ACK:
				//clear buffer
				memset(segment, 0, sizeof(RDTHeader));
			
				//fill header
				hdr->sequence_number = htonl(this->sequence_number);
				hdr->ack_number = htonl(0);
				hdr->type = RDT_CLOSE;
			
				if (send(this->sock_fd, segment, sizeof(RDTHeader), 0) < 0) {
					cerr << "Couldn't send ack ack\n";
				}
				else{
					cerr << "Sent ack ack\n";	
					state = CLOSE;
				}
			break;

			case CLOSE:
				if (close(this->sock_fd) < 0) {
					cerr << "Couldn't close connection\n";
				}
				else{
					cerr << "Connection closed\n";
					this->state = CLOSED;
					return;
				}
		
			break;
		}
	}

}

void ReliableSocket::receiver_close(){
	int state = RECEIVE_CLOSE;

	char segment[sizeof(RDTHeader)];
	RDTHeader* hdr = (RDTHeader*)segment;
	
	int rtt = 0;
	//state machine 
	while(1){
		switch(state){
			case RECEIVE_CLOSE:	
				//clear buffer
				memset(segment, 0, sizeof(RDTHeader));
				//read in message
				if(recv(this->sock_fd, segment, sizeof(RDTHeader), 0) < 0){
					cerr << "did not receive closing message\n";
				}else if(hdr->type == RDT_CLOSE){
					//expected sequence number
					if(ntohl(hdr->sequence_number) == expected_sequence_number){
						cerr << "Received closing message\n";
						//start rtt timer
						rtt = current_msec();
						state = ACK_CLOSE;
					}
				}
				break;
			case ACK_CLOSE:	
				//clear buffer
				memset(segment, 0, sizeof(RDTHeader));
				
				hdr->sequence_number = htonl(this->sequence_number + 1);
				hdr->ack_number = htonl(0);
				hdr->type = RDT_CLOSE;
				
				if (send(this->sock_fd, segment, sizeof(RDTHeader), 0) < 0) {
					cerr << "Couldn't ack close\n";
					state = CLOSE;
				}else{
					cerr << "Acked close message\n";
					state = RECEIVE_ACK_ACK;
				}

				break;
			case RECEIVE_ACK_ACK:
				//clear buffer
				memset(segment, 0, sizeof(RDTHeader));
				//read in message
				if (recv(this->sock_fd, segment, sizeof(RDTHeader), 0) < 0) {
					cerr << "Did not receive ack ack\n";
					had_timeout();
					state = ACK_CLOSE;
				}else {
					if(hdr->type == RDT_CLOSE && ntohl(hdr->sequence_number)
						== expected_sequence_number + 1){
						cerr << "Verified close\n";
						//end rtt timer
						rtt = current_msec() - rtt;
						EWMA(rtt);

						state = CLOSE;
					}
				}
				
				break;
			case CLOSE:
				if (close(this->sock_fd) < 0) {
					cerr << "Couldn't close connection\n";
				}
				else{
					cerr << "Connection closed\n";
					this->state = CLOSED;
					return;
				}
				break;
		}
	}
}
