#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

#include "dns.h"

#define MAX_QUERY_SIZE 1024
#define MAX_RESPONSE_SIZE 4096
#define DNS_HEADER_SIZE 12
#define DEBUG true

//store header in struct
DNSHeader getHeader(uint8_t *response){
	DNSHeader head;
	head.id = (response[0] << 8) + response[1];
	head.flags = (response[2]<<8)+response[3];
	head.q_count = (response[4]<<8)+response[5];
	head.a_count = (response[6]<<8)+response[7];
	head.auth_count = (response[8]<<8)+response[9];	
	head.other_count = (response[10]<<8)+response[11];
	
	if(DEBUG){		
		printf("flags: %x\n", head.flags);
		printf("questions: %x\n", head.q_count);
		printf("answer rr's: %x\n", head.a_count);
		printf("authority rr's: %x\n", head.auth_count);
		printf("additional rr's: %x\n", head.other_count);
	}
	
	return head;
}

DNSRecord getRecord(uint8_t *response){
	DNSRecord record;
		
	record.name = (response[0]<<8) + response[1];
	record.type = (response[2]<<8) + response[3];
	record.class = (response[4]<<8) + response[5];
	record.ttl = (response[6]<<24) + (response[7]<<16) + (response[8]<<8) + response[9];
	record.datalen = (response[10]<<8) + response[11];

	//TODO populate record.data using datalen the data startss at response[12]
	//and goes until response[12+datalen]
	//need to figure out how to store data section
	record.data = NULL;
	if(DEBUG){
		printf("record name: %04x ",record.name);	
		printf("record type: %04x ",record.type);
		printf("record class: %04x ",record.class);
		printf("record ttl: %08x ",record.ttl);
		printf("record datalen: %04x\n", record.datalen);
	}
	return record;
}

int getNameLength(uint8_t *name){
	int pointer=0;
	int length=0;
		
	while(name[pointer] != 0){
		length += name[pointer] + 1;
		pointer = length;
	}
	//account for last label 
	return length+1;
}

//get root server list from file
char ** getRootServers(char * file);

//unsure of return value needs to recursively call resolve until we get the
//right response
bool recurseResolve(char * hostname, uint8_t qType, char ** rootList, int timeout);

// Note: uint8_t* is a pointer to 8 bits of data.

/**
 * Constructs a DNS query for hostname's Type A record.
 *
 * @param query Pointer to memory where query will stored.
 * @param hostname The host we are trying to resolve
 * @return The number of bytes in the constructed query.
 */
int construct_query(uint8_t* query, char* hostname, bool isMX) {
	memset(query, 0, MAX_QUERY_SIZE);

	// first part of the query is a fixed size header
	DNSHeader *hdr = (DNSHeader*)query;

	// set ID to 5... you should randomize this!
	hdr->id = htons(5);

	// set header flags to request iterative query
	hdr->flags = htons(0x0000);	

	// 1 question, no answers or other records
	hdr->q_count=htons(1);
	hdr->a_count=htons(0);
	hdr->auth_count=htons(0);
	hdr->other_count=htons(0);

	// We are going to have to wade into pointer arithmetic here since our
	// struct is a fixed size but our queries will be variably sized.

	// add the name
	int query_len = sizeof(DNSHeader); 
	int name_len = convertStringToDNS(hostname,query+query_len);
	query_len += name_len; 
	
	// set the query type to A or mx
	uint16_t *type = (uint16_t*)(query+query_len);
	if(isMX)	*type = htons(15);
	else 		*type = htons(1);
	query_len+=2;

	// finally the class: INET
	uint16_t *class = (uint16_t*)(query+query_len);
	*class = htons(1);
	query_len += 2;
	
	printf("query length: %d\n", query_len); 
	return query_len;
}

/**
 * Returns a string with the IP address (for an A record) or name of mail
 * server associated with the given hostname.
 *
 * @param hostname The name of the host to resolve.
 * @param is_mx True (1) if requesting the MX record result, False (0) if
 *    requesting the A record.
 *
 * @return A string representation of an IP address (e.g. "192.168.0.1") or
 *   mail server (e.g. "mail.google.com"). If the request could not be
 *   resolved, NULL will be returned.
 */
char* resolve(char *hostname, bool is_mx) {

	if (is_mx == false) {
		printf("Requesting A record for %s\n", hostname);
	}
	else {
		printf("Requesting MX record for %s\n", hostname);
	}

	// create a UDP (i.e. Datagram) socket
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(0);
	}
	// Create a time value structure and set it to five seconds.
	struct timeval tv;
	memset(&tv, 0, sizeof(struct timeval));
	tv.tv_sec = 5;

	/* Tell the OS to use that time value as a time out for operations on
	 * our socket. */
	int res = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv,
			sizeof(struct timeval));

	if (res < 0) {
		perror("setsockopt");
		exit(0);
	}

	// The following is the IP address of USD's local DNS server. It is a
	// placeholder only (i.e. you shouldn't have this hardcoded into your final
	// program).
	in_addr_t nameserver_addr = inet_addr("172.16.7.15");
	
	//in_addr_t nameserver_addr = inet_addr("198.41.0.4");
	
	struct sockaddr_in addr; 	// internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53); // port 53 for DNS
	addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)

	// uint8_t is a standard, unsigned 8-bit value.
	// You should use that type for all buffers used for sending to and
	// receiving from the DNS server.
	uint8_t query[MAX_QUERY_SIZE]; 
	int query_len=construct_query(query, hostname, is_mx);

	int send_count = sendto(sock, query, query_len, 0,
							(struct sockaddr*)&addr, sizeof(addr));

	if (send_count<0) { 
		perror("Send failed");
		exit(1);
	}

	socklen_t len = sizeof(struct sockaddr_in);

	uint8_t response[MAX_RESPONSE_SIZE];

	/* Blocking calls will now return error (-1) after the timeout period with
	 * errno set to EAGAIN. */
	res = recvfrom(sock, response, MAX_RESPONSE_SIZE, 0, 
					(struct sockaddr *)&addr, &len);

	if (res < 1) {
		if (errno == EAGAIN) {
			printf("Timed out!\n");
		} else {
			perror("recv");
		}
	}

	// TODO: The server's response will be located in the response array for you
	// to further process and extract the needed information.
	// Remember that DNS is a binary protocol: if you try printing out response
	// as a string, it won't work correctly.
	
	//read the header into a struct
	DNSHeader head = getHeader(response); 
	
	//12 = size of header
	int nameLen = getNameLength(response+DNS_HEADER_SIZE);
	//+4 for type and class this is where the first record is located in the
	//response
	int	recordIndex = DNS_HEADER_SIZE + nameLen + 4;		
	
	DNSRecord Answers[head.a_count];
	for(int i = 0; i < head.a_count; i++){
		if(DEBUG) printf("Record #: %d ", i);
		Answers[i] = getRecord(response+recordIndex);
		recordIndex += 12 + Answers[i].datalen;
		if(DEBUG) printf("index: %d\n ", recordIndex);	
	
		// I think this is where we handle type: A = ipv4 AAAA = ipv6 MX= mail
		// server CNAME = canonical name 
		//if (Answers[i].type == 1)
			//this gives a seg fault rn because we arent adding data to the
			//records yet in the getrecord function
			//printf("Found an ipv4 address!\n Here it is: %d.%d.%d.%d\n", Answers[i].data[0], Answers[i].data[1], Answers[i].data[2], Answers[i].data[3]);
	}		
	
	//make array of auth servers
	DNSRecord AuthRecords[head.auth_count];
	for(int i = 0; i < head.auth_count; i++){
		if(DEBUG) printf("Record #: %d ", i);
		AuthRecords[i] = getRecord(response+recordIndex);
		recordIndex += 12 + AuthRecords[i].datalen;
		if(DEBUG) printf("index: %d\n ", recordIndex);	
	}
	
	//make array of additional records not sure if we need this but its easy
	//to add 
	DNSRecord AddRecords[head.other_count];	
	for(int i = 0; i < head.other_count; i++){
		if(DEBUG) printf("Record #: %d ", i);
		AddRecords[i] = getRecord(response+recordIndex);
		recordIndex += 12 + AddRecords[i].datalen;
		if(DEBUG) printf("index: %d\n ", recordIndex);	
	}
	
	//we need to call this same function the the ip addresses of the auth
	//responses 
	return NULL;
}


int main(int argc, char **argv) {
	bool isMX;
	char *url;
	
	//one CLI input
	if(argc == 2){
		isMX = false;
		url = argv[1];
	}
	//two CLI inputs
	else if (argc == 3) {
		if (strcmp(argv[1], "-m") == 0) {
			isMX = true;
			url = argv[2];
			//TODO need to chop off www from the url here
		}
		//bad flag
		else { 
			printf("Invalid program usage\n");
			return 1;
		}
	}
	//wrong number of inputs. print out usage here
	else {
		// TODO: provide a more helpful message on how to use the program
		printf("Invalid program usage for %s!\n", argv[0]);
		return 1;
	}

	char *answer = resolve(url, isMX);
	
	if (answer != NULL) {
		printf("Answer: %s\n", answer);
	}
	else {
		printf("Could not resolve request.\n");
	}

	return 0;
}
