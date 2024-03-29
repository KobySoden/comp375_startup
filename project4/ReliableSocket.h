/*
 * File: ReliableSocket.h
 *
 * Header / API file for library that provides reliable data transport over an
 * unreliable link.
 *
 */

enum RDTMessageType : uint8_t {RDT_CONN, RDT_CLOSE, RDT_ACK, RDT_DATA};

/**
 * Format for the header of a segment send by our reliable socket.
 */
struct RDTHeader {
	uint32_t sequence_number;
	uint32_t ack_number;
	uint32_t length;
	RDTMessageType type;
};

enum connection_status {INIT, SYN_SENT, SYN_RECEIVED,
ESTABLISHED, RECEIVED_CLOSE, CLOSED };


/**
 * Class that represents a socket using a reliable data transport protocol.
 * This socket uses a stop-and-wait protocol so your data is sent at a nice,
 * leisurely pace.
 */
class ReliableSocket {
public:
	/*
	 * You probably shouldn't add any more public members to this class.
	 * Any new functions or fields you need to add should be private.
	 */
	
	// These are constants for all reliable connections
	static const int MAX_SEG_SIZE  = 1400;
	static const int MAX_DATA_SIZE = MAX_SEG_SIZE - sizeof(RDTHeader);

	/**
	 * Basic Constructor, setting estimated RTT to 100 and deviation RTT to 10.
	 */
	ReliableSocket();

	/**
	 * Connects to the specified remote hostname on the given port.
	 *
	 * @param hostname Name of the remote host to connect to.
	 * @param port_num Port number of remote host.
	 */
	void connect_to_remote(char *hostname, int port_num);

	/**
	 * Waits for a connection attempt from a remote host.
	 *
	 * @param port_num The port number to listen on.
	 */
	void accept_connection(int port_num);

	/**
	 * Send data to connected remote host.
	 *
	 * @param buffer The buffer with data to be sent.
	 * @param length The amount of data in the buffer to send.
	 */
	void send_data(const void *buffer, int length);

	/**
	 * Receives data from remote host using a reliable connection.
	 *
	 * @param buffer The buffer where received data will be stored.
	 * @return The amount of data actually received.
	 */
	int receive_data(char buffer[MAX_DATA_SIZE]);

	/**
	 * Closes an connection.
	 */
	void close_connection();

	/**
	 * Returns the estimated RTT.
	 * 
	 * @return Estimated RTT for connection (in milliseconds)
	 */
	uint32_t get_estimated_rtt();

private:
	// Private member variables are initialized in the constructor
	int sock_fd;
	uint32_t sequence_number;
	uint32_t expected_sequence_number;
	int estimated_rtt;
	int dev_rtt;
	int timeout;
	int receiver_rtt;
	connection_status state;

	// In the (unlik:ely?) event you need a new field, add it here.

	/**
	 * Sets the timeout length of this connection.
	 *
	 * @note Setting this to 0 makes the timeout length indefinite (i.e. could
	 * wait forever for a message).
	 *
	 * @param timeout_length_ms Length of timeout period in milliseconds.
	 */
	void set_timeout_length(uint32_t timeout_length_ms);

	/**
	 * Reliably sends data using stop and wait with acks
	 *
	 * @param buffer buffer containing the data to be sent
	 * @param length length of the data to be sent
	 */
	 void RDTSend(const void *buffer, int length);
	
	/**
	 * Reliably recieves data using stop and wait with acks
	 *
	 * @param buffer stores data being received
	 * @return number of bytes received
	 */
	 int RDTReceive(char *buffer);

	/**
	 * Exponential weighted moving average calculation for estiamted rtt and
	 * deviation of rtt 
	 *
	 * @param rtt measured rtt from the last packet
	 */	
	 void EWMA(int rtt);
	
	/**	
	 * increases timeout value when there has been a timeout
	 *
	 */
	 void had_timeout();
	
	/*
	 * function used to handle closing connection sequence for the reciever
	 */
	 void receiver_close();
};
