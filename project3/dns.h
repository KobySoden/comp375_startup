/*
 * This file contains some useful structs and functions for working with DNS
 * messages.
 */

#include <stdint.h>

//forward declaring these functions here; they are described more in detail in
//resolver.c 
char* resolve(char *hostname, bool is_mx);
char* recurseResolve(char *hostname, bool is_mx, char* IP);

/**
 * DNS header structure.
 * Most of the message is variable size, which means we can't declare them in
 * this C struct.
 * When creating a DNSHeader, you'll want to allocate the sizeof the struct
 * plus extra bytes to handle the variable sized data.
 * This approach is going to force you to do some pointer arithmetic though.
 */
struct DNSRecordAnswer {
	// first a variable sized name, then
	uint8_t *name_answer;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t datalen;
	// and then a variable sized data field
	uint8_t *data;
	int len_dns_name;
} __attribute__((packed));

typedef struct DNSRecordAnswer DNSRecordAnswer;

struct DNSHeader {
	uint16_t id, flags, q_count, a_count, auth_count, other_count;	
	// variable number of questions
	// variable number of answer resource records
	// variable number of authoritative server records
	// variable number of other resource records
} __attribute__((packed));

typedef struct DNSHeader DNSHeader;

/**
 * DNS Resource record structure.
 * Like the header, there is a variably sized component (the data) that is not
 * part of this struct.
 */
struct DNSRecord {
	// first a variable sized name, then
	uint8_t *name;
	uint16_t type;
	uint16_t class;
//	uint32_t ttl;
//	uint16_t datalen;
	// and then a variable sized data field
//	uint8_t *data;
} __attribute__((packed));

typedef struct DNSRecord DNSRecord;

/**
 * Converts our normal C-style string (e.g. www.sandiego.edu) to the DNS-style
 * string (e.g. (3)www(8)sandiego(3)edu(0).
 *
 * @param str_name The string you want to convert.
 * @param dns_name The DNS-style equivalent to str_name
 * @returns Length of dns_name
 */
int convertStringToDNS(char* str_name, uint8_t* dns_name) {
	int part_len=0;
	for (unsigned i=0; i < strlen(str_name); i++) {
		if (str_name[i] != '.') {
			dns_name[i+1]=str_name[i];
			part_len++;
		}
		else {
			dns_name[i-part_len]=part_len;
			part_len=0;
		}
	}

	dns_name[strlen(str_name)-part_len] = part_len;
	dns_name[strlen(str_name)+1] = 0;
	return strlen(str_name)+2;
}

/**
 * Converts a DNS-style string (e.g. (3)www(8)sandiego(3)edu(0) to the normal
 * C-style string (e.g. www.sandiego.edu).
 * This supports DNS-style name compression (see RFC 1035, Section 4.1.4).
 *
 * @info You need to pass in a pointer to the start of the DNS message with
 * the DNS-style string so we can determine if the name is compressed or not.
 *
 * @param message Pointer to beginning of DNS response message that contains
 * 					the DNS-style string you are trying to convert.
 * @param dns_name The DNS-style name string to convert.
 * @param str_name The normal version of dns_name 
 * @return The number of bytes of dns_name read.
 */
int getStringFromDNS(uint8_t *message, uint8_t *dns_name, char *str_name) {
	uint8_t part_remainder = 0;
	int len = 0;
	int return_len = 0;
	uint8_t *orig_name = dns_name;
	while (*dns_name) {
		if (part_remainder == 0) {
			// this condition checks for message compression, see RFC 1035 4.1.4
			if ((*dns_name) >= 0xc0) { 
				if (return_len==0)
					return_len = (dns_name-orig_name)+2;
				dns_name=message+(((*dns_name)&0x3f) << 8) + *(dns_name+1);
				continue;
			}
			else {
				part_remainder = *dns_name;
				if (len > 0)
					str_name[len++] = '.';
			}
		}
		else {
			str_name[len++] = *dns_name;
			part_remainder--;
		}
		dns_name++;
	}
	str_name[len]=0;
	return (return_len ? return_len : dns_name-orig_name+1);
}
