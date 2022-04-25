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
#define DEBUG false
#define Atype 1
#define MXtype 15

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
		printf("flags: %x ", head.flags);
		printf("questions: %d ", head.q_count);
		printf("answer rr's: %d ", head.a_count);
		printf("authority rr's: %d ", head.auth_count);
		printf("additional rr's: %d\n", head.other_count);
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

	record.data = (uint8_t*) malloc(record.datalen * sizeof(uint8_t));
	if (DEBUG) printf("data: ");
	for (int i = 0; i < record.datalen; i++){
		record.data[i] = response[12+i];
		if (DEBUG && record.datalen == 4) printf("%03d.", record.data[i]);
		if (DEBUG && record.datalen != 4) printf("%02x.", record.data[i]);
	}	
	if(DEBUG){
		printf(" name: %04x ",record.name);	
		printf("type: %04x ",record.type);
		printf("class: %04x ",record.class);
		printf("ttl: %08x ",record.ttl);
		printf("datalen: %04x\n", record.datalen);
	}
	return record;
}

void freeRecords(DNSRecord * records, int numRecords){
	for(int i = 0; i < numRecords; i++){
		free(records[i].data);
	}
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
//this is generally how I think we can read from the root-servers.txt and put
//all the addresses in a list. I don't think the way I return in this function
//is right yet though, and same with the type of function it is
char ** getRootServers(char * file)
{
	FILE *root_file;
	size_t len = 0;
	ssize_t read;

	//maximum of 128 lines can be read in	
	char ** root_list = (char **) malloc(128 * sizeof(char *));
	memset(root_list, 0, 128 * sizeof(char *));
	root_file = fopen(file, "r");

	if (root_file == NULL) {
		printf("error opening root file");
		return NULL;
	}

	int lineCount = 0;

	//read file line by line
	while ((read = getline(&root_list[lineCount], &len, root_file)) != -1) {
		lineCount++;
    }
	
	fclose(root_file);
	return root_list; 
}


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
	
	return query_len;
}

char* getIPFromRecord(DNSRecord record) {
			char * str = (char*)malloc(30 * sizeof(char));
			char * str2 = (char*)malloc(30 * sizeof(char));
			
			memset(str, 0, 30* sizeof(char));
			memset(str2, 0, 30* sizeof(char));
			for(int j = 0; j < record.datalen; j++)
			{					
				sprintf(str2, "%d", (int)record.data[j]);
				strcat(str, str2);
				if (j < record.datalen - 1) strcat(str, ".");
			}

			free(str2);
			//free str at some point after it has been used
			return str;
	}

uint8_t * sendQuery(char *destIp, char* hostname, bool is_mx){	
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

	// The following is the IP address of USD's local DNS server.
	//in_addr_t nameserver_addr = inet_addr("172.16.7.15\n");
	
	in_addr_t nameserver_addr = inet_addr(destIp);

	
	struct sockaddr_in addr; 	// internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53); // port 53 for DNS
	addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)

	uint8_t query[MAX_QUERY_SIZE]; 
	int query_len=construct_query(query, hostname, is_mx);

	int send_count = sendto(sock, query, query_len, 0,
							(struct sockaddr*)&addr, sizeof(addr));

	if (send_count<0) { 
		perror("Send failed");
		exit(1);
	}

	socklen_t len = sizeof(struct sockaddr_in);

	uint8_t * response = (uint8_t *) malloc(MAX_RESPONSE_SIZE * sizeof(uint8_t));
	/* Blocking calls will now return error (-1) after the timeout period with
	 * errno set to EAGAIN. */
	res = recvfrom(sock, response, MAX_RESPONSE_SIZE, 0, 
					(struct sockaddr *)&addr, &len);

	if (res < 1) {
		if (errno == EAGAIN) {
			perror("Timed out!");
		} else {
			perror("recv");

		}
		return NULL;
	}
	return response;
	
}

char* recurseResolve(char *hostname, bool is_mx, char *destIp) {
	printf("Sending your request to: %s\n", destIp);

	uint8_t *response = sendQuery(destIp, hostname, is_mx);
	
	if (response == NULL){
		 return NULL;
	}
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
		
		if(i < 0) free(Answers[i-1].data);
			
		// I think this is where we handle type: A = ipv4 AAAA = ipv6 MX= mail 
		if (Answers[i].type == Atype)
		{
			char * ip = getIPFromRecord(Answers[i]); 
			free(Answers[i].data);
			free(response);
			return ip;
		}			
	//	else if (Answers[i].type == MXtype) 
	//	{
	//		char * ip = getIPFromRecord(Answers[i]);
	//		free(Answers[i].data);
	//		free(response);
	//		return //I think this has to return the name version of the ip
	//	}
	
	}		
	if(head.a_count > 0) free(Answers[head.a_count-1].data);
	
	//make array of auth servers
	DNSRecord AuthRecords[head.auth_count];
	for(int i = 0; i < head.auth_count; i++){
		if(DEBUG) printf("Record #: %d ", i);
		AuthRecords[i] = getRecord(response+recordIndex);
		recordIndex += 12 + AuthRecords[i].datalen;
		if(DEBUG) printf("index: %d\n", recordIndex);	
		
		
		if(i > 0) {
			free(AuthRecords[i-1].data);
		}
			
		// might need recursion here
	}
	if(head.auth_count > 0) free(AuthRecords[head.auth_count-1].data);
	
	//make array of additional records this is where I found the ip for google
	DNSRecord AddRecords[head.other_count];
	for(int i = 0; i < head.other_count; i++){
		if(DEBUG) printf("Record #: %d ", i);
		AddRecords[i] = getRecord(response+recordIndex);
		recordIndex += 12 + AddRecords[i].datalen;
		if(DEBUG) printf("index: %d\n", recordIndex);
		
		if(i > 0) {
			free(AddRecords[i-1].data);
		}
		
		//entrypoint to recursion
		if (AddRecords[i].datalen == 4){ 
			char * serverIp = getIPFromRecord(AddRecords[i]);
			char * ip = recurseResolve(hostname, is_mx, serverIp);
			free(serverIp);
			if(ip != NULL){ 
				free(AddRecords[i].data);
				free(response);
				return ip;
			}
			free(ip);
		}
			
	}
	if(head.other_count > 0) free(AddRecords[head.other_count-1].data);
		
	free(response);	
	return NULL;
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
	char ** root_list = getRootServers("root-servers.txt");
	
	if (is_mx == false) {
		printf("Requesting A record for %s\n", hostname);
	}
	else {
		printf("Requesting MX record for %s\n", hostname);
	}
	
	char * ip = NULL;
	int i = 0;
	while(ip == NULL){
		ip =  recurseResolve(hostname, is_mx, root_list[i]);
		i++; 
	}
	//need to free root list before returning
	for(int i = 0; i < 128; i++) free(root_list[i]);
	free(root_list);
	return ip;
}

void printErrorMessages() {

	printf("Invalid program usage\n");
	printf("Format for using this program for a Type A record request: ./resolver [insert subdomain hostname here]\n");	
	printf("Example using this format: ./resolver www.google.com\n\n");
	printf("Format for using this program for a Type MX record request: ./resolver -m [insert domain hostname here]\n");
	printf("Example using this format: ./resolver -m google.com\n\n");
}

int main(int argc, char **argv) {
	bool isMX;
	char *url;

	//one CLI input meaning it is a Type A request
	if(argc == 2){
		isMX = false;
		url = argv[1];
		
	//if url does not start with a valid subdomain such as www, home, san, ole
	//then print error messages
	//
	//
		if (argv[1][0] == 119 && argv[1][1] == 119 && argv[1][2] == 119)
		{
		//continues if url starts with www
		}
		else if (argv[1][0] == 104 && argv[1][1] == 111 && argv[1][2] == 109 && argv[1][3] == 101)
		{
		//continues if url starts with home
		}
		else if (argv[1][0] == 115 && argv[1][1] == 97 && argv[1][2] == 110)
		{
		//continues if url starts with san
		}
		else if (argv[1][0] == 111 && argv[1][1] == 108 && argv[1][2] == 101)
		{
		//continues if url starts with ole
		}
		else
		{
			printErrorMessages(); //prints error messages if not any of the subdomains above
			return 1;
		}
			
//TODO need to find a way to check if the actual domain is valid. So far I've
//been able handle invalid subdomains and TLDs but checking the domain is
//tricky since I think you have to look at wireshark response for a bad domain
//to determine how to check for an invalid one
			
	//if url does not end in a valid TLD such as .com, .net, .edu, .gov, .ru, .io then print error
	//messages
	//This checks the ascii of the characters
		if (argv[1][strlen(argv[1])-3] == 99 && argv[1][strlen(argv[1])-2] == 111 && argv[1][strlen(argv[1])-1] == 109)
		{
		//	continues if url ends in .com
		}
		else if (argv[1][strlen(argv[1])-3] == 110 && argv[1][strlen(argv[1])-2] == 101 && argv[1][strlen(argv[1])-1] == 116)
		{
		//	continues if url ends in .net
		}	
		else if (argv[1][strlen(argv[1])-3] == 101 && argv[1][strlen(argv[1])-2] == 100 && argv[1][strlen(argv[1])-1] == 117)
		{
		//	continues if url ends in .edu
		}
		else if (argv[1][strlen(argv[1])-3] == 103 && argv[1][strlen(argv[1])-2] == 111 && argv[1][strlen(argv[1])-1] == 118)
		{
		//	continues if url ends in .gov
		}
		else if (argv[1][strlen(argv[1])-2] == 114 && argv[1][strlen(argv[1])-1] == 117)
		{
		//	continues if url ends in .ru 
		}
		else if (argv[1][strlen(argv[1])-2] == 105 && argv[1][strlen(argv[1])-1] == 111)
		{
		// continues ir url ends in .io
		}
		else
		{
			printErrorMessages(); //prints error messages if not any of the TLD's listed above
			return 1;
		}

	}
	//two CLI inputs meaning it is a Type MX request
	else if (argc == 3) {
		if (strcmp(argv[1], "-m") == 0) {
			isMX = true;
			url = argv[2];

			//handles when requesting for a Type MX record with a subdomain of www, home, san, ole when
			//it should just be the domain. This checks the ascii of the
			//characters
			if ((argv[2][0] == 119 && argv[2][1] == 119 && argv[2][2] == 119)
				||(argv[1][0] == 104 && argv[1][1] == 111 && argv[1][2] == 109 && argv[1][3] == 101)
				||(argv[1][0] == 115 && argv[1][1] == 97 && argv[1][2] == 110)
				||(argv[1][0] == 111 && argv[1][1] == 108 && argv[1][2] == 101))
			{
				printf("\nCannot resolve MX subdomain request (SOA), please try again with the domain hostname\n");
				return 1;
			}

//TODO need to find a way to check if the actual domain is valid. So far I've
//been able handle invalid subdomains and TLDs but checking the domain is
//tricky since I think you have to look at wireshark response for a bad domain
//to determine how to check for an invalid one

		//if url does not end in a valid TLD such as .com, .net, .edu, .gov, .ru, .io then print error
		//messages
		//This checks the ascii of the characters

			if (argv[1][strlen(argv[2])] == 99 && argv[1][strlen(argv[2])+1] == 111 && argv[1][strlen(argv[2])+2] == 109)
		 	{
			//	continues if url ends in .com
		    }
			else if (argv[1][strlen(argv[2])] == 110 && argv[1][strlen(argv[2])+1] == 101 && argv[1][strlen(argv[2])+2] == 116)
			{
			//	continues if url ends in .net
			}	
			else if (argv[1][strlen(argv[2])] == 101 && argv[1][strlen(argv[2])+1] == 100 && argv[1][strlen(argv[2])+2] == 117)
			{
			//	continues if url ends in .edu
			}
			else if (argv[1][strlen(argv[2])] == 103 && argv[1][strlen(argv[2])+1] == 111 && argv[1][strlen(argv[2])+2] == 118)
			{
			//	continues if url ends in .gov
			}
			else if (argv[1][strlen(argv[2])+1] == 114 && argv[1][strlen(argv[2])+2] == 117)
			{
			//	continues if url ends in .ru 
			}
			else if (argv[1][strlen(argv[2])+1] == 105 && argv[1][strlen(argv[2])+2] == 111)
			{
			// continues ir url ends in .io
			}
			else
			{
				printErrorMessages(); //prints error messages if not any of the TLD's listed above
				return 1;
			}

		}
		else { 
			printErrorMessages();
			return 1;
		}
	}
	//wrong number of inputs. print out usage here
	else {
		// TODO: provide a more helpful message on how to use the program
		printErrorMessages();
		return 1;
	}

	char *answer = resolve(url, isMX);
	
	if (answer != NULL) {
		printf("Answer: %s\n", answer);
	}
	else {
		printf("Could not resolve request.\n");
	}
	free(answer);
	return 0;
}
