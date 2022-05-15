/**************************************
#define _GNU_SOURCE
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
#define NStype 2
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

*************************************************************************/

/**
 * Constructs a DNS query for hostname's Type A record.
 *
 * @param query Pointer to memory where query will stored.
 * @param hostname The host we are trying to resolve
 * @return The number of bytes in the constructed query.
 */
/************************************************************************
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
**********************************************************************************/
	/* Tell the OS to use that time value as a time out for operations on
	 * our socket. */
	/***************************************************************************
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
	********************************************************************************************/
	/* Blocking calls will now return error (-1) after the timeout period with
	 * errno set to EAGAIN. */
	/**********************************************************************************
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
	
	printf("\nHELLO\n");
	printf("\n%d\n", recordIndex);

	DNSRecord Answers[head.a_count];
	for(int i = 0; i < head.a_count; i++){
		if(DEBUG) printf("Record #: %d ", i);
		Answers[i] = getRecord(response+recordIndex);
		recordIndex += 12 + Answers[i].datalen;
		if(DEBUG) printf("index: %d\n ", recordIndex);	
		
		if(i < 0) free(Answers[i-1].data);
			
		// I think this is where we handle type: A = ipv4 AAAA = ipv6 MX= mail
		char * ip = NULL; 
		if (Answers[i].type == Atype)
		{
			ip = getIPFromRecord(Answers[i]);
			printf("\nHELLO\n");
			printf("\n%s\n", ip);
			free(Answers[i].data);
			free(response);
			return ip;
		}	
		
//		else if (Answers[i].type == NStype)
//		{
//		    ip = getIPFromRecord(Answers[i]);
//			printf("\n%s\n", ip);
//          free(Answers[i].data);
//          free(response);
//          return ip;
//		}

//		else if (Answers[i].type == MXtype) 
//		{
//			int MX_IP;
//			char * mailName = NULL;
//			MX_IP = getStringFromDNS(response+recordIndex, Answers[i].data, mailName);
//			printf("\n%d\n", MX_IP);
//			free(Answers[i].data);
//			free(response);	
//			return mailName; //I think this has to return the name version of the ip
//		}
	
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
//		if (AuthRecords[i].type == NStype)
//		{  
//		 	char str[1024];
//			getStringFromDNS(response+recordIndex, response+recordIndex+12, str);
//			printf("\n%s\n", ip);
			
//          free(AuthRecords[i].data);
//			free(response);

//			char ** root_list = getRootServers("root-servers.txt");
	
//			char * ip = NULL;
//			int i = 0;
//			while(ip == NULL && i < 12){
//				ip =  recurseResolve(str, is_mx, root_list[i]);
//				i++; 
//			}
			//printf("IP = %s\n", ip);
		
//			if(ip != NULL) return recurseResolve(hostname, is_mx, ip);
		}
//		recordIndex += 12 + AuthRecords[i].datalen;
//	}
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

*****************************************************************************************/
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
/*********************************************************************************
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
*********************************************************************************************************************/
/* COMP375 Project 03: Iterative DNS Resolver
 * Authors: Andres Mallea (amallea@sandiego.edu)
 * 			Koby Soden (ksoden@sandiego.edu)
 *
 * In this project we take in a hostname as an argument and ping a list of
 * root servers from a text file to try and resolve the IP address for that
 * hostname. If we get an answer then we return that IP address and if we
 * don't get an answer then the root server gets an IP of a DNS server that 
 * we can ping to try and find the answer. We keep iteratively pinging the 
 * next DNS server down the hierarchy of servers until we find an answer. 
 * This program supports requesting for Type A records and Type MX records.
 * Also performs error checking and prints user friendly and helpful messages. 
 */

//libraries we need for project syntax to be recognized
#define _GNU_SOURCE
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

//defined a variable debug to make debugging easier and defined some constant values
#define DEBUG false
#define MAX_QUERY_SIZE 1024
#define MAX_RESPONSE_SIZE 4096

/**
 * Parses through the DNS response's header information.
 * Spent multiple hours on wireshark here making sure each header is parsed
 * correctly with the correct amount of storage allocated to it
 *
 * @param response Pointer to the response of the DNS query
 *
 * @return Structure that has all the DNS query header information stored
 */
DNSHeader getHeader(uint8_t *response) {
	DNSHeader header;
	header.id = (response[0] << 8) + response[1];
	header.flags = (response[2] << 8) + response[3];
	header.q_count = (response[4] << 8) + response[5];
	header.a_count = (response[6] << 8) + response[7];
	header.auth_count = (response[8] << 8) + response[9];
	header.other_count = (response[10] << 8) + response[11];

	//helps print out how many records we get back from an answer
	if(DEBUG) {	
		printf("flags: %x ", header.flags);
		printf("questions: %d ", header.q_count);
		printf("answer rr's: %d ", header.a_count);
		printf("authority rr's: %d ", header.auth_count);
		printf("additional rr's: %d\n", header.other_count);
	}	
	return header;
}

/**
 * Parses through the DNS record information.
 * Spent multiple hours on wireshark here making sure each record is parsed
 * correctly with the correct amount of storage allocated to it
 *
 * @param response Pointer to the response of the DNS query
 * @param record_query Structure where all records will be stored
 * @param name_len length of the variable sized query name
 *
 * @return Structure that has all the DNS query record information stored
 */
DNSRecord getRecord(uint8_t *response, DNSRecord record_query, int name_len) {
	for (int i = 0; i < (name_len); i++) {
		record_query.name[i] = response[i];
	}
	record_query.type = response[name_len + 1] + (response[name_len] << 8);
	record_query.class = response[name_len + 3] + (response[name_len + 2] << 8);

	return record_query;
}

/**
 * Parses through the DNS record answer information which contains the IP we
 * are trying to resolve.
 * Spent multiple hours on wireshark here making sure each record answer is parsed
 * correctly with the correct amount of storage allocated to it
 *
 * @param response Pointer to the response of the DNS query
 * @param response_index The index at which the response is currently parsed at
 * @param record_answer Structure where all record answers will be stored
 * @param is_mx True if an MX record is requested, False if an
 *               A record is requested
 */
DNSRecordAnswer getRecordAnswer(uint8_t *response, int response_index, DNSRecordAnswer record_answer, bool is_mx) {
	char* str_name = malloc(sizeof(char) * 500);
		int len_dns_name = getStringFromDNS(response, &response[response_index], str_name);
		free(str_name);
		record_answer.len_dns_name = len_dns_name;
		record_answer.name_answer = malloc(sizeof(uint8_t)*len_dns_name);

		for(int i = 0; i < (len_dns_name); i++) {
			record_answer.name_answer[i] = response[response_index + 1];
		}
		record_answer.type = response[response_index + len_dns_name + 1] + (response[response_index + len_dns_name] << 8);
		record_answer.class = response[response_index + len_dns_name + 3] + (response[response_index + len_dns_name + 2] << 8);
		record_answer.ttl = response[response_index + len_dns_name + 7] + (response[response_index + len_dns_name + 6] << 8) + (response[response_index + len_dns_name + 5] << 16) + (response[response_index + len_dns_name + 4] << 24);
		record_answer.datalen = response[response_index + len_dns_name + 9] + (response[response_index + len_dns_name + 8] << 8);
	int preference_buffer = 0;

	if(is_mx) {
		preference_buffer = 2;
	}
		record_answer.data = malloc(record_answer.datalen * sizeof(uint8_t));
		for(int i = 0; i < record_answer.datalen; i++) {
			record_answer.data[i] = response[preference_buffer + response_index + len_dns_name + 10 + i];
		}
		free(record_answer.name_answer);
		return record_answer;
}
/**
 * Constructs a DNS query for hostname's Type A record.
 *
 * @param query Pointer to memory where query will stored.
 * @param hostname The host we are trying to resolve
 * @param is_mx True if an MX record is requested, False if an
 *              A record is requested
 *
 * @return The number of bytes in the constructed query.
 */
int construct_query(uint8_t* query, char* hostname, bool is_mx) {
	memset(query, 0, MAX_QUERY_SIZE);

	// first part of the query is a fixed header
	DNSHeader *hdr = (DNSHeader*)query;

	// set ID to 5... you should randomize this!
	// hdr->id = htons(5);
	hdr->id = htons(rand()%65635);

	// set header flags to request iterative query
	hdr->flags = htons(0x0000);

	// 1 question, no answers or other records
	hdr->q_count = htons(1);
	hdr->a_count = htons(0);
	hdr->auth_count = htons(0);
	hdr->other_count = htons(0);

	// We are going to have to wade into pointer arithmetic here since our 
	// struct is a fixed size but our queries will be variably sized.
	
	// add the name
	int query_len = sizeof(DNSHeader);
	int name_len = convertStringToDNS(hostname,query+query_len);
	query_len += name_len;

	// set the query type to A or mx
	uint16_t *type = (uint16_t*)(query+query_len);
	if(is_mx) {  
		*type = htons(15);
	}
	else {   
		*type = htons(1);
	}
	query_len += 2;
	
	// finally the class: INET
	uint16_t *class = (uint16_t*)(query+query_len);
	*class = htons(1);
	query_len += 2;

	return query_len;
}

/**
 * Opens a socket connection and sends the query that requests for either an A
 * record or an MX record.
 *
 * @param hostname The host we are trying to resolve.
 * @param is_mx True (1) if requesting the MX record result, False (0) if 
 *              requesting the A record.
 * @param IP String with next IP to ping to resolve hostname
 *
 * @return A string representation of an IP address (e.g. "192.168.0.1") or
 *   mail server (e.g. "mail.google.com"). If the request could not be
 *   resolved, NULL will be returned.
 *        
 */
uint8_t* send_query(char* hostname, bool is_mx, char* IP) {
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

	int res = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));

	if (res < 0) {
		perror("setsockopt");
		exit(0);
	}

	// The following is the IP address of USD's local DNS server.
	//in_addr_t nameserver_addr = inet_addr("172.16.7.15\n");

	in_addr_t nameserver_addr = inet_addr(IP);

	struct sockaddr_in addr;    // internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53); // port 53 for DNS
	addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)

	uint8_t query[MAX_QUERY_SIZE];
	int query_len = construct_query(query, hostname, is_mx);

	int send_count = sendto(sock, query, query_len, 0, (struct sockaddr*)&addr, sizeof(addr));

	if (send_count < 0) {
		perror("Send failed");
		exit(1);
	}

	socklen_t len = sizeof(struct sockaddr_in);

	uint8_t * response = (uint8_t*) malloc(MAX_RESPONSE_SIZE * sizeof(uint8_t));

	/* Blocking calls will now return error (-1) after the timeout period with
	 * errno set to EAGAIN. */

	res = recvfrom(sock, response, MAX_RESPONSE_SIZE, 0, (struct sockaddr *)&addr, &len);

	if (res < 1) {
		if (errno == EAGAIN) {
			perror("Timed out!\n");
		}
		else {
			perror("recv");
		}
		return NULL;
	}
	return response;
}

/**
 * This function handles when we are recursively trying to resolve for a hostname with a type A record.
 * If we run into an NS or CNAME server it handles it by using the functions
 * we were given in the header file to perform string conversions
 *
 * @param hostname The name of the host to resolve.
 * @param is_mx True (1) if requesting the MX record result, False (0) if 
 *               requesting the A record.
 * @param response Pointer to the response of the DNS query
 * @param response_index The index at which the response is currently parsed at
 * @param header Structure that contains the response's header information
 * from the DNS query 
 *
 * @return A string representation of an IP address (e.g. "192.168.0.1") or
 * mail server (e.g. "mail.google.com"). If the request could not be
 * resolved, NULL will be returned.
 */
char* typeARequestHandler(char* hostname, bool is_mx, uint8_t* response, int response_index, DNSHeader header) {
	char* answer;
	DNSRecordAnswer record_answer;

	if(header.a_count > 0) {
		record_answer = getRecordAnswer(response, response_index, record_answer, is_mx);

		if(record_answer.type == 1) {
			answer = malloc(sizeof(char)*16);
			answer[0] = '\0';
			char address_num_str[3];
			for(int i = 0; i < record_answer.datalen; i++) {
				sprintf(address_num_str, "%d", record_answer.data[i]);
				strcat(answer, address_num_str);
				if(i<3) {
					strcat(answer, ".");
					}
			}
			free(response);
			free(record_answer.data);
			return answer;
		}
		else if (record_answer.type == 5) {
			char* str_name = (char*)malloc(500*sizeof(char));
			char cname[getStringFromDNS(response, record_answer.data, str_name)];
			strcpy(cname, str_name);
			free(record_answer.data);
			free(str_name);
			free(response);
			return resolve(cname, is_mx);
		}
		
		else {
			printf("\nERROR\nReceived a record answer not of type 1 (A) or type 5 (NS)\n");
			exit(-1);
		}
		response_index += record_answer.len_dns_name + 10 + record_answer.datalen;
	}

	else if(header.other_count > 0 && header.auth_count > 0) {
		while(header.auth_count > 0) {
			record_answer = getRecordAnswer(response, response_index, record_answer, false);
			response_index += record_answer.len_dns_name + 10 + record_answer.datalen;
			free(record_answer.data);
			header.auth_count--;
		}
		while(header.other_count > 0) {
			record_answer = getRecordAnswer(response, response_index, record_answer, false);
			if(record_answer.type == 1) {
				char *IP = (char*)malloc(sizeof(char)*16);
				char address_num_str[3];
				IP[0] = '\0';
				for(int i = 0; i < record_answer.datalen; i++) {
					sprintf(address_num_str, "%d", record_answer.data[i]);
					strcat(IP, address_num_str);
					if(i < 3) {
						strcat(IP, ".");
					}
				}

				answer = recurseResolve(hostname, is_mx, IP);
				free(IP);

				if (answer != NULL) {
					free(record_answer.data);
					free(response);
					return answer;
				}
				free(answer);
			}
			response_index += record_answer.len_dns_name + 10 + record_answer.datalen;
			header.other_count --;
			free(record_answer.data);
		}
	}

	else if(header.auth_count > 0 && header.other_count == 0) {
		while(header.auth_count > 0) {
			record_answer = getRecordAnswer(response, response_index, record_answer, false);

			if(record_answer.type == 2) {
				char* str_name = (char*)malloc((500)*sizeof(char));
				char nsname[getStringFromDNS(response, record_answer.data, str_name)];
				strcpy(nsname, str_name);
				free(str_name);
				char *newIP;
				newIP = resolve(nsname, is_mx);
				if(newIP == NULL){
					continue;
				}
				answer = recurseResolve(hostname, is_mx, newIP);
				free(newIP);
				if(answer != NULL){
					free(record_answer.data);
					free(response);
					return answer;
				}
				free(answer);
			}
			response_index += record_answer.len_dns_name + 10 + record_answer.datalen;
			free(record_answer.data);
			header.auth_count--;
		}
	}
	else{
		printf("\nERROR\n No answer record, no authoritative record");
		exit(-1);
	}

	free(response);
	return NULL;
}

/**
 * This function handles when we are recursively trying to resolve for a hostname with a type MX record.
 * If we run into an NS or CNAME server it handles it by using the functions
 * we were given in the header file to perform string conversions
 *
 * @param hostname The name of the host to resolve.
 * @param is_mx True (1) if requesting the MX record result, False (0) if 
 *               requesting the A record.
 * @param response Pointer to the response of the DNS query
 * @param response_index The index at which the response is currently parsed at
 * @param header Structure that contains the response's header information
 * from the DNS query 
 *
 * @return A string representation of an IP address (e.g. "192.168.0.1") or
 * mail server (e.g. "mail.google.com"). If the request could not be
 * resolved, NULL will be returned.
 */
char* typeMXRequestHandler(char* hostname, bool is_mx, uint8_t* response, int response_index, DNSHeader header) {
	char* answer;
	DNSRecordAnswer record_answer;

	if(header.a_count > 0) {
		record_answer = getRecordAnswer(response, response_index, record_answer, is_mx);

		if(record_answer.type == 15) {
			char* str_name = (char*)malloc(500*sizeof(char));
			getStringFromDNS(response, record_answer.data, str_name);
			free(record_answer.data);
			free(response);
			return str_name;
		}
		else {
			printf("\nERROR\nReceived a record answer not of type 15 (MX)\n");
			exit(-1);
		}
		response_index += 12 + record_answer.len_dns_name;
	}
	else if(header.other_count > 0 && header.auth_count > 0) {
		while(header.auth_count > 0) {
			record_answer = getRecordAnswer(response, response_index, record_answer, false);
			response_index += record_answer.len_dns_name + 10 + record_answer.datalen;
			free(record_answer.data);
			header.auth_count--;
		}
		while(header.other_count > 0) {
			record_answer = getRecordAnswer(response, response_index, record_answer, false);
			if(record_answer.type == 1) {
				char *IP = (char*)malloc(sizeof(char)*16);
				char address_num_str[3];
				IP[0] = '\0';
				for(int i = 0; i < record_answer.datalen; i++) {
					sprintf(address_num_str, "%d", record_answer.data[i]);
					strcat(IP, address_num_str);
					if(i < 3) {
						strcat(IP, ".");
					}
				}

				answer = recurseResolve(hostname, is_mx, IP);
				free(IP);

				if (answer != NULL) {
					free(record_answer.data);
					free(response);
					return answer;
				}
				free(answer);
			}
			response_index += record_answer.len_dns_name + 10 + record_answer.datalen;
			header.other_count --;
			free(record_answer.data);
		}
	}
	else if(header.auth_count > 0 && header.other_count == 0) {
		while(header.auth_count > 0) {
			record_answer = getRecordAnswer(response, response_index, record_answer, false);

			if(record_answer.type == 2) {
				char* str_name = (char*)malloc((500)*sizeof(char));
				char nsname[getStringFromDNS(response, record_answer.data, str_name)];
				strcpy(nsname, str_name);
				free(str_name);
				char *newIP;
				newIP = resolve(nsname, false);
				if(newIP == NULL){
					continue;
				}
				answer = recurseResolve(hostname, is_mx, newIP);
				free(newIP);
				if(answer != NULL){
					free(record_answer.data);
					free(response);
					return answer;
				}
				free(answer);
			}
			response_index += record_answer.len_dns_name + 10 + record_answer.datalen;
			free(record_answer.data);
			header.auth_count--;
		}
	}
	else{
		printf("\nERROR\n No answer record, no authoritative record");
		exit(-1);
	}
	free(response);
	return NULL;
}

/**
 * Handles sending the resolve request to the specific handler for each type of request (either A or MX) 
 *
 * @param hostname The name of the host to resolve.
 * @param is_mx True (1) if requesting the MX record result, False (0) if 
 *               requesting the A record.
 * @param response Pointer to the response of the DNS query
 * 
 * @return A string representation of an IP address (e.g. "192.168.0.1") or
 * mail server (e.g. "mail.google.com"). If the request could not be
 * resolved, NULL will be returned.
 */
char* resolveTypeHandler(char* hostname, bool is_mx, uint8_t* response) {
	int response_index = 0;
	DNSHeader header = getHeader(response);
	response_index = 12;

	uint8_t *dns_name = malloc((strlen(hostname) + 2 )*sizeof(uint8_t));
	int len_dns_name = convertStringToDNS(hostname, dns_name);
	free(dns_name);

	DNSRecord record_query;
	record_query.name = malloc(len_dns_name * sizeof(uint8_t));
	record_query = getRecord(&response[response_index], record_query, len_dns_name);
	char dns_name_converted[len_dns_name + 1];
	getStringFromDNS(&response[response_index], record_query.name, dns_name_converted);
	response_index += len_dns_name + 4;

	free(record_query.name);
	if(is_mx){
		return typeMXRequestHandler(hostname, is_mx, response, response_index, header);
	}
	else{
		return typeARequestHandler(hostname, is_mx, response, response_index, header);
	}
}

/**
 * Initiates recursion by resolving a given IP recursively by calling the type
 * handler
 * Returns a string with the IP address (for an A record) or name of mail
 * server associated with the given hostname
 *
 * @param hostname The name of the host to resolve.
 * @param is_mx True (1) if requesting the MX record result, False (0) if 
 *    requesting the A record.
 *
 * @return A string representation of an IP address (e.g. "192.168.0.1") or
 *   mail server (e.g. "mail.google.com"). If the request could not be
 *   resolved, NULL will be returned.
 */
char* recurseResolve(char *hostname, bool is_mx, char* IP) {
	char* answer;
	if (is_mx == false) {
		printf("Sending your request for %s to %s\n", hostname, IP);
	}
	else {
		printf("Sending your request for %s to %s\n", hostname, IP);
	}
	uint8_t*response = send_query(hostname, is_mx, IP);
	if(response == NULL){
		return NULL;
	}
	answer = resolveTypeHandler(hostname, is_mx, response);
	return answer;
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
	FILE *root_servers_file;
	root_servers_file = fopen("root-servers.txt", "r");
	char lines_in_file[80];
	if(root_servers_file == NULL) {
		printf("error opening root-servers.txt");
		return NULL;
	}

	char* answer;
	while(fgets(lines_in_file, 80, root_servers_file)) {
		if (is_mx == false) {
			printf("Sending your request for %s to %s", hostname, lines_in_file);
		}
		else {
			printf("Sending your request for %s to %s", hostname, lines_in_file);
		}
		uint8_t *response = send_query(hostname, is_mx, lines_in_file);
		if(response == NULL) {
			continue;
		}
        answer = resolveTypeHandler(hostname, is_mx, response);
		if(answer != NULL) {
			fclose(root_servers_file);
			return answer;
		}
	}
	fclose(root_servers_file);
	return answer;
}

/**
 * When this function is called user friendly messages are printed in order to
 * let the user know an error has occured and demonstrates how to properly run
 * the program 
 */
void printErrorMessages() {

	printf("Invalid program usage\n");
	printf("Format for using this program for a Type A record request: ./resolver [insert subdomain hostname here]\n");	
	printf("Example using this format: ./resolver www.google.com\n\n");
	printf("Format for using this program for a Type MX record request: ./resolver -m [insert domain hostname here]\n");
	printf("Example using this format: ./resolver -m google.com\n\n");
}

/**
 * Main function that is executed first when running the program. Checks to
 * see how many arguments are entered by the user so it knows whether to
 * request for an A record or and MX record. Also calls a function that prints
 * user friendly error messages if program was not executed properly with
 * correct argument formatting.
 *
 * @param argc the number of arguments passed into main function
 * @param argv pointer to an array that stores the arguments passed into main
 *             function
 *
 * @return 0 if program executes and exits without error
 */
int main(int argc, char **argv) {
	char *answer;
	//checks if there are less than 2 arguments when running program
	if (argc < 2) {
		printErrorMessages();
		exit(2);
	}
	//checks to see if there are 2 arguments meaning it is a type A record
	//request
	else if (argc == 2) {
		printf("Requesting an A record for %s\n", argv[1]); 
		answer = resolve(argv[1], false);
	}
	//checks to see if there are 3 arguments meaning it is a type MX record
	//request
	else if (argc == 3 && strcmp(argv[1], "-m") == 0) {
		printf("Requesting and MX record for %s\n", argv[2]);
		answer = resolve(argv[2], true);
	}
	else {
		printErrorMessages();	
		exit(2);
	}
	//prints the resolved mail exchange for MX lookup
	if (answer != NULL && strcmp(argv[1], "-m") == 0) {
		printf("The mail exchange for %s resolves to: %s\n", argv[2], answer);
	}
	//prints the resolved IP for A lookup
	else if (answer != NULL) {
		printf("The name %s resolves to: %s\n", argv[1], answer);
	}
	else {
		printErrorMessages();
	}
	free(answer);
	return 0;
}





