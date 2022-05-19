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

//header file that includes some forward delcared functions and also includes
//some important functions that can perform string-DNS name conversions
#include "dns.h"

//defined a variable debug to make debugging easier and defined some constant values
#define DEBUG false

//defined constants
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
	//parses the header info
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
	//parses the record info
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
	//allocate space for record answers and parse through them and store in
	//struct
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

	//checks if MX is requested so we can allocate space and parse differently for those
	//records
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

	//checks if there is an answer in the header
	if(header.a_count > 0) {
		record_answer = getRecordAnswer(response, response_index, record_answer, is_mx);

		//checks if answer record is a type A
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

		//checks if answer record is a type CNAME
		else if (record_answer.type == 5) {
			char* str_name = (char*)malloc(500*sizeof(char));
			char cname[getStringFromDNS(response, record_answer.data, str_name)];
			strcpy(cname, str_name);
			free(record_answer.data);
			free(str_name);
			free(response);
			return resolve(cname, is_mx);
		}
		
		//handle error if not A or NS record
		else {
			printf("\nERROR\nReceived a record answer not of type 1 (A) or type 5 (NS)\n");
			exit(-1);
		}
		response_index += record_answer.len_dns_name + 10 + record_answer.datalen;
	}

	//checks if there is no answer in the header
	else if(header.other_count > 0 && header.auth_count > 0) {
		while(header.auth_count > 0) {
			record_answer = getRecordAnswer(response, response_index, record_answer, false);
			response_index += record_answer.len_dns_name + 10 + record_answer.datalen;
			free(record_answer.data);
			header.auth_count--;
		}
		while(header.other_count > 0) {
			record_answer = getRecordAnswer(response, response_index, record_answer, false);

			//checks if answer record is a type A
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

				//calls recurseResolve to continue recursively iterating through server hiearchy with next IP
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
	
	//checks if there are no answers in the header or auth records
	else if(header.auth_count > 0 && header.other_count == 0) {
		while(header.auth_count > 0) {
			record_answer = getRecordAnswer(response, response_index, record_answer, false);

			//checks if answer record is a type NS
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

				//calls recurseResolve to continue recursively iterating through server hiearchy with next IP
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

	//handle if there is no answer record at all
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

	//checks if there is an answer in the header
	if(header.a_count > 0) {
		record_answer = getRecordAnswer(response, response_index, record_answer, is_mx);

		//checks if answer record is a type MX
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

	//checks if there is no answer in the header
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

				//calls recurseResolve to continue recursively iterating through server hiearchy with next IP
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

	//checks if there are no answers in the header or auth records
	else if(header.auth_count > 0 && header.other_count == 0) {
		while(header.auth_count > 0) {
			record_answer = getRecordAnswer(response, response_index, record_answer, false);

			//checks if answer record is a type NS
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

				//calls recurseResolve to continue recursively iterating through server hiearchy with next IP
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

	//handle if there is no answer record at all
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
	//parses header
	int response_index = 0;
	DNSHeader header = getHeader(response);
	response_index = 12;

	//gets length of DNS name
	uint8_t *dns_name = malloc((strlen(hostname) + 2 )*sizeof(uint8_t));
	int len_dns_name = convertStringToDNS(hostname, dns_name);
	free(dns_name);

	//parses query
	DNSRecord record_query;
	record_query.name = malloc(len_dns_name * sizeof(uint8_t));
	record_query = getRecord(&response[response_index], record_query, len_dns_name);
	char dns_name_converted[len_dns_name + 1];
	getStringFromDNS(&response[response_index], record_query.name, dns_name_converted); //converts record DNS name to string format
	response_index += len_dns_name + 4;

	free(record_query.name);

	//handles which type handler function to send it to depending on resolve
	//request 
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

	//prints progress output as we are recursively traversing server hierarchy
	if (is_mx == false) {
		printf("Sending your request for %s to %s\n", hostname, IP);
	}
	else {
		printf("Sending your request for %s to %s\n", hostname, IP);
	}
	uint8_t*response = send_query(hostname, is_mx, IP);

	//return NULL if response is NULL so it skips it
	if(response == NULL){
		return NULL;
	}
	
	//send to handler function to process the response
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
	//opens and reads the root-servers.txt file inside the current directory
	//goes through each line of the file
	FILE *root_servers_file;
	root_servers_file = fopen("root-servers.txt", "r");
	char lines_in_file[80];
	if(root_servers_file == NULL) {
		printf("error opening root-servers.txt");
		return NULL;
	}

	char* answer;

	//prints progress output as we traverse the file IPs
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
	//print user friendly messages if user trys to run program with incorrect
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
	//print user friendly messages if user trys to run program with incorrect
	//format
	else {
		printErrorMessages();
	}
	free(answer);
	return 0;
}





