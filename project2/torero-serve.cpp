/**
 * ToreroServe: A Lean Web Server
 * COMP 375 - Project 02
 *
 * This program should take two arguments:
 * 	1. The port number on which to bind and listen for connections
 * 	2. The directory out of which to serve files.
 * This program initializes a web server at the port specified and gives users
 * access to the directory tree specified in argument 2. Users can view
 * images, html files and navigate the directory specified.
 *
 *
 * Author 1: Kevin McDonald kmcdonald@sandiego.edu
 * Author 2: Koby Soden ksoden@sandiego.edu
 */

// standard C libraries
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>

// operating system specific libraries
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>

// C++ standard libraries
#include <vector>
#include <thread>
#include <string>
#include <iostream>
#include <system_error>
#include <filesystem>
#include <regex>
#include <fstream>

#include "BoundedBuffer.hpp"

// shorten the std::filesystem namespace down to just fs
namespace fs = std::filesystem;

using std::cout;
using std::string;
using std::vector;
using std::thread;

// This will limit how many clients can be waiting for a connection.
static const int BACKLOG = 10;
const size_t MAX_THREADS = 10;
const size_t BUFF_CAP = 20;

// forward declarations
int createSocketAndListen(const int port_num);
void acceptConnections(const int server_sock, std::string curDir);
void handleClient(const int client_sock, std::string curDir);
void sendData(int socked_fd, const char *data, size_t data_length);
int receiveData(int socked_fd, char *dest, size_t buff_size);

bool isValid(std::string request);
bool fileDNE(std::string file);
void pageDNE(const int client_sock);
void sendBadReq(const int client_sock);
void sendFile(const int client_sock, std::string file);
void sendHeader (const int client_sock, std::string file);
void sendDir(const int client_sock, string curDir);
void waitForClient(BoundedBuffer &buf, string curDir);

//buffer for sending and recieving
#define BUFF_SIZE 4096

int main(int argc, char** argv) {

	/* Make sure the user called our program correctly. */
	if (argc != 3) {
		cout << "INCORRECT USAGE!\n";
		cout << "./torero-serve [Port] [WWW]\n";
		exit(1);
	}

    /* Read the port number from the first command line argument. */
    int port = std::stoi(argv[1]);

	/* Create a socket and start listening for new connections on the
	 * specified port. */
	int server_sock = createSocketAndListen(port);

	/* Now let's start accepting connections. */
	acceptConnections(server_sock, argv[2]);

    close(server_sock);

	return 0;
}

/**
 * Sends message over given socket, raising an exception if there was a problem
 * sending.
 *
 * @param socket_fd The socket to send data over.
 * @param data The data to send.
 * @param data_length Number of bytes of data to send.
 */
void sendData(int socked_fd, const char *data, size_t data_length) {
	
	int num_bytes_sent;
	
	while(data_length > 0){	
		num_bytes_sent = send(socked_fd, data, data_length, 0);
		if (num_bytes_sent == -1) {
			std::error_code ec(errno, std::generic_category());
			throw std::system_error(ec, "send failed");
		}
		data += num_bytes_sent;
		data_length -= num_bytes_sent;
	}
}

/**
 * Receives message over given socket, raising an exception if there was an
 * error in receiving.
 *
 * @param socket_fd The socket to send data over.
 * @param dest The buffer where we will store the received data.
 * @param buff_size Number of bytes in the buffer.
 * @return The number of bytes received and written to the destination buffer.
 */
int receiveData(int socked_fd, char *dest, size_t buff_size) {
	int num_bytes_received = recv(socked_fd, dest, buff_size, 0);
	if (num_bytes_received == -1) {
		std::error_code ec(errno, std::generic_category());
		throw std::system_error(ec, "recv failed");
	}

	return num_bytes_received;
}

/**
 * Receives a request from a connected HTTP client and sends back the
 * appropriate response.
 *
 * @note After this function returns, client_sock will have been closed (i.e.
 * may not be used again).
 *
 * @param client_sock The client's socket file descriptor.
 * @param curDir the current directory or file being examined
 */
void handleClient(const int client_sock, std::string curDir) {
	// Step 1: Receive the request message from the client
	char received_data[BUFF_SIZE];
	int bytes_received = receiveData(client_sock, received_data, BUFF_SIZE);

	// Turn the char array into a C++ string for easier processing.
	string request_string(received_data, bytes_received);
		
	//check for valid get request.
	if(!isValid(request_string)){
		sendBadReq(client_sock);
		close(client_sock);
		return;
	}
	
	//get filename from http request	
	std::istringstream s(request_string);
	std::string file;
	getline(s, file, ' ');
	getline(s, file, ' ');

	//append filename to directory
	curDir.append(file);
	
	//check if user is requesting a directory
	if(fs::is_directory(curDir)) sendDir(client_sock,curDir);
	
	//check if the file exists
	else if(fileDNE(curDir)) pageDNE(client_sock);
	
	//file exists and is not a directory so send the file
	else {
		sendHeader(client_sock, curDir);
		sendFile(client_sock,curDir);	
	}

	// Close connection with client.
	close(client_sock);
}

/**
 * Creates a new socket and starts listening on that socket for new
 * connections.
 *
 * @param port_num The port number on which to listen for connections.
 * @returns The socket file descriptor
 */
int createSocketAndListen(const int port_num) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Creating socket failed");
        exit(1);
    }

    /* 
	 * A server socket is bound to a port, which it will listen on for incoming
     * connections.  By default, when a bound socket is closed, the OS waits a
     * couple of minutes before allowing the port to be re-used.  This is
     * inconvenient when you're developing an application, since it means that
     * you have to wait a minute or two after you run to try things again, so
     * we can disable the wait time by setting a socket option called
     * SO_REUSEADDR, which tells the OS that we want to be able to immediately
     * re-bind to that same port. See the socket(7) man page ("man 7 socket")
     * and setsockopt(2) pages for more details about socket options.
	 */
    int reuse_true = 1;

	int retval; // for checking return values

    retval = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse_true,
                        sizeof(reuse_true));

    if (retval < 0) {
        perror("Setting socket option failed");
        exit(1);
    }

    /*
	 * Create an address structure.  This is very similar to what we saw on the
     * client side, only this time, we're not telling the OS where to connect,
     * we're telling it to bind to a particular address and port to receive
     * incoming connections.  Like the client side, we must use htons() to put
     * the port number in network byte order.  When specifying the IP address,
     * we use a special constant, INADDR_ANY, which tells the OS to bind to all
     * of the system's addresses.  If your machine has multiple network
     * interfaces, and you only wanted to accept connections from one of them,
     * you could supply the address of the interface you wanted to use here.
	 */
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_num);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* 
	 * As its name implies, this system call asks the OS to bind the socket to
     * address and port specified above.
	 */
    retval = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (retval < 0) {
        perror("Error binding to port");
        exit(1);
    }

    /* 
	 * Now that we've bound to an address and port, we tell the OS that we're
     * ready to start listening for client connections. This effectively
	 * activates the server socket. BACKLOG (a global constant defined above)
	 * tells the OS how much space to reserve for incoming connections that have
	 * not yet been accepted.
	 */
    retval = listen(sock, BACKLOG);
    if (retval < 0) {
        perror("Error listening for connections");
        exit(1);
    }

	return sock;
}

/**
 * Sit around forever accepting new connections from client.
 *
 * @param server_sock The socket used by the server.
 * @param curDir current dirrectory for serving files
 */
void acceptConnections(const int server_sock, std::string curDir) {
	
	BoundedBuffer buf(BUFF_CAP);
   	
	//create threads tell them to wait for clients
	for (size_t i = 0; i<MAX_THREADS; ++i){
		std::thread listener(waitForClient,std::ref(buf),curDir);
		//release threads so that they dont have to rejoin
		listener.detach();
	}
	
	while (true) {
        // Declare a socket for the client connection.
        int sock;
		
        /* 
		 * Another address structure.  This time, the system will automatically
         * fill it in, when we accept a connection, to tell us where the
         * connection came from.
		 */
        struct sockaddr_in remote_addr;
        unsigned int socklen = sizeof(remote_addr); 

        /* 
		 * Accept the first waiting connection from the server socket and
         * populate the address information.  The result (sock) is a socket
         * descriptor for the conversation with the newly connected client.  If
         * there are no pending connections in the back log, this function will
         * block indefinitely while waiting for a client connection to be made.
         */
        sock = accept(server_sock, (struct sockaddr*) &remote_addr, &socklen);
        if (sock < 0) {
            perror("Error accepting connection");
            exit(1);
        }

        //put sockets into buffer for threads to take out
    	buf.putItem(sock);
	}
}
/* check for valid http formatting
 *
 * @param request the http request being examined
 */
bool isValid(std::string request){
	//make regular expression matching template for get request
	std::regex http_get_regex("(GET\\s[\\w\\-\\./]*\\sHTTP/\\d\\.\\d)");
	std::smatch get_match;
	//compare input string to template 
	if (std::regex_search(request, get_match, http_get_regex)) return true;
	return false;
}
/*
 *check if a file exists
 *
 * @param file relative path to a file
 */
bool fileDNE(std::string file){
	//create filestream and check for errors
	std::ifstream f(file.c_str());
    return !f.good();

}
/*
 *Send HTTP 400 bad request response message
 *
 *@param client_sock the client socket used to send the message
 */
void sendBadReq(const int client_sock){
	string badReq = "HTTP/1.1 400 BAD REQUEST\r\n";
	sendData(client_sock, badReq.c_str(), badReq.length());
	string error;
	error = "<html>\r\n<head>\r\n<title>INVALID REQUEST</title>\r\n</head>\r\n<body>400 BAD REQUEST :'(</body>\r\n</html>\r\n";  
	std::stringstream ack;
	ack << "Content-Type: text/html\r\nContent-Lenth: " <<  error.length() << "\r\n\r\n" << error <<  "\r\n"; 
	string fullAck = ack.str();
	sendData(client_sock, fullAck.c_str(), fullAck.length());
}
/*
 * send 404 error message and display web page
 *
 * @param client_sock the client socket being used to send the message
 */
void pageDNE (const int client_sock){
	string issue = "HTTP/1.1 404 PAGE NOT FOUND";
	sendData(client_sock, issue.c_str(), issue.length());
	string error;
	error = "<html>\r\n<head>\r\n<title> PAGE NOT FOUND </title>\r\n</head>\r\n<body>404 Page Not Found :'(</body>\r\n</html>\r\n";  
	std::stringstream ack;
	ack << "Content-Type: text/html\r\nContent-Lenth: " <<  error.length() << "\r\n\r\n" << error <<  "\r\n"; 
	string fullAck = ack.str();
	sendData(client_sock, fullAck.c_str(), fullAck.length());

}

/*
 * send file to the client
 *
 * @param client_sock the client socket being used to send the message
 * @param file relative path to the file being sent
 */
void sendFile(const int client_sock, string file){
	//open file stream to read from file	
	std::ifstream file_stream(file, std::ios::binary);
	char data[BUFF_SIZE];
	//iterate through file and send each iteration to client
	while(!file_stream.eof()){
		file_stream.read(data,BUFF_SIZE);
		int bytes = file_stream.gcount();
		sendData(client_sock, data, bytes);
	}
	file_stream.close();
	sendData(client_sock, "\r\n", sizeof("\r\n"));
}
/*
 *send html header message to client
 *
 *@param client_sock the client socket being used to send
 *@param file relative path to a file that is about to be sent
 */
void sendHeader (const int client_sock, string file){
	//look for file extension
	std::regex expression("\\.\\w*");
	std::smatch rMatch;
	string size;
	std::stringstream header;
	
	header << "Content-Type: ";
	//determine file type
	if(std::regex_search(file, rMatch, expression)){
		if (rMatch[0]==".css"){
			header << "text/css";
		}
		else if (rMatch[0] == ".html"){
			header << "text/html";
		}
		else if (rMatch[0] == ".pdf"){
			header << "application/pdf";
		}
		else if (rMatch[0] == ".jpg"){
			header << "image/jpg";
		}
		else if (rMatch[0] == ".png"){
			header << "image/png";
		}
		else if (rMatch[0] == ".gif"){
			header << "image/gif";
		}
		else if(rMatch[0] == ".plain"){
			header << "text/plain";
		}
	}
	else{
		cout << "file type " << rMatch[0].str() <<" is not supported";
		return;
	}
	header << "\r\n" << "Content-Length: " << std::to_string(fs::file_size(file)) << "\r\n\r\n";
	string finalHeader = header.str();
	//send http response
	string ok = "HTTP/1.1 200 Looking Good\r\n";
	sendData(client_sock,  ok.c_str(), ok.length());
	//send header
	sendData(client_sock,  finalHeader.c_str(), finalHeader.length());
}		
/*
 * wait for a client to connect
 *
 * @param &buf a reference to the bounded buffer where client sockets are
 * stored
 * @param curDir directory where files are being served from
 */ 
void waitForClient(BoundedBuffer &buf, string curDir){
	while(1){
		int socks = buf.getItem();
		handleClient(socks, curDir);
	}
}
/*
 *send the contents of a directory in bulleted list format
 *
 * @param client_sock the client socked used for sending
 * @param curDir the directory that is being printed
 */
void sendDir(const int client_sock, string curDir){
	//create html to start adding files to
	std::stringstream makeList;
	makeList << "<html>\r\n<head><title>" << curDir << "</title></head>\r\n<body>\r\n<ul>\r\n";
	//iterate through all the files in curDir
	for(auto const& fileNames: fs::directory_iterator(curDir)){
		//if an index.html file is found serve this instead of the list of
		//files
		if(fileNames.path().filename() == "index.html"){
			sendHeader(client_sock, fileNames.path());
			sendFile(client_sock, fileNames.path());
			return;
		}
		//if the file is regular add it to the list with a link to open it 
		else if(fs::is_regular_file(curDir + fileNames.path().filename().string())){
			makeList << "\t<li><a href=\"" << fileNames.path().filename().string() << "\">" << fileNames.path().filename().string() << "</a></li>\r\n";
		}
		//if the file is a directory add it to the list with a link to open it
		else if (fs::is_directory(curDir + fileNames.path().filename().string())){
			makeList << "\t<li><a href=\"" << fileNames.path().filename().string() << "/\">" <<  fileNames.path().filename().string() << "/</a></li>\r\n";
		}
	}
	//finish html formatting
	makeList << "</ul>\r\n</body>\r\n</html>\r\n";
	string list = makeList.str();

	//attach the content type and length to the top of the html file
	std::stringstream finalResponse;
	finalResponse << "Content-Type: text/html\r\nContent-Length: " << list.length() << "\r\n\r\n" << list << "\r\n";
	string send = finalResponse.str();	
	
	//send 200 ok http response
	string ok = "HTTP/1.1 200 Looking Good\r\n";
	sendData(client_sock,  ok.c_str(), ok.length());
	
	//send html file created above
	sendData(client_sock, send.c_str(),send.length()); 
}
