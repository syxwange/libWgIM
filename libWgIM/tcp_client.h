#pragma once

#include <QObject>

#include <sodium.h>
#include "network.h"


#ifdef TCP_SERVER_USE_EPOLL
#include "sys/epoll.h"
#endif

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32) || defined(__MACH__)
#define MSG_NOSIGNAL 0
#endif

#define MAX_INCOMMING_CONNECTIONS 256

#define TCP_MAX_BACKLOG MAX_INCOMMING_CONNECTIONS

#define MAX_PACKET_SIZE 2048

#define TCP_HANDSHAKE_PLAIN_SIZE (crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES)
#define TCP_SERVER_HANDSHAKE_SIZE (crypto_box_NONCEBYTES + TCP_HANDSHAKE_PLAIN_SIZE + crypto_box_MACBYTES)
#define TCP_CLIENT_HANDSHAKE_SIZE (crypto_box_PUBLICKEYBYTES + TCP_SERVER_HANDSHAKE_SIZE)
#define TCP_MAX_OOB_DATA_LENGTH 1024

#define NUM_RESERVED_PORTS 16
#define NUM_CLIENT_CONNECTIONS (256 - NUM_RESERVED_PORTS)

#define TCP_PACKET_ROUTING_REQUEST  0
#define TCP_PACKET_ROUTING_RESPONSE 1
#define TCP_PACKET_CONNECTION_NOTIFICATION 2
#define TCP_PACKET_DISCONNECT_NOTIFICATION 3
#define TCP_PACKET_PING 4
#define TCP_PACKET_PONG 5
#define TCP_PACKET_OOB_SEND 6
#define TCP_PACKET_OOB_RECV 7
#define TCP_PACKET_ONION_REQUEST  8
#define TCP_PACKET_ONION_RESPONSE 9

#define ARRAY_ENTRY_SIZE 6

/* frequency to ping connected nodes and timeout in seconds */
#define TCP_PING_FREQUENCY 30
#define TCP_PING_TIMEOUT 10

#ifdef TCP_SERVER_USE_EPOLL
#define TCP_SOCKET_LISTENING 0
#define TCP_SOCKET_INCOMING 1
#define TCP_SOCKET_UNCONFIRMED 2
#define TCP_SOCKET_CONFIRMED 3
#endif

enum {
	TCP_STATUS_NO_STATUS,
	TCP_STATUS_CONNECTED,
	TCP_STATUS_UNCONFIRMED,
	TCP_STATUS_CONFIRMED,
};

typedef struct TCP_Priority_List {
	TCP_Priority_List* next;
	uint16_t size, sent;
	uint8_t data[];
}TCP_Priority_List;



typedef struct {
	IP_Port ip_port;
	uint8_t proxy_type; // a value from TCP_PROXY_TYPE
} TCP_Proxy_Info;

typedef struct {
	uint8_t status;
	sock_t  sock;
	uint8_t self_public_key[crypto_box_PUBLICKEYBYTES]; /* our public key */
	uint8_t public_key[crypto_box_PUBLICKEYBYTES]; /* public key of the server */
	IP_Port ip_port; /* The ip and port of the server */
	TCP_Proxy_Info proxy_info;
	uint8_t recv_nonce[crypto_box_NONCEBYTES]; /* Nonce of received packets. */
	uint8_t sent_nonce[crypto_box_NONCEBYTES]; /* Nonce of sent packets. */
	uint8_t shared_key[crypto_box_BEFORENMBYTES];
	uint16_t next_packet_length;

	uint8_t temp_secret_key[crypto_box_SECRETKEYBYTES];

	uint8_t last_packet[2 + MAX_PACKET_SIZE];
	uint16_t last_packet_length;
	uint16_t last_packet_sent;

	TCP_Priority_List* priority_queue_start, * priority_queue_end;

	uint64_t kill_at;

	uint64_t last_pinged;
	uint64_t ping_id;

	uint64_t ping_response_id;
	uint64_t ping_request_id;

	struct {
		uint8_t status; /* 0 if not used, 1 if other is offline, 2 if other is online. */
		uint8_t public_key[crypto_box_PUBLICKEYBYTES];
		uint32_t number;
	} connections[NUM_CLIENT_CONNECTIONS];
	int (*response_callback)(void* object, uint8_t connection_id, const uint8_t* public_key);
	void* response_callback_object;
	int (*status_callback)(void* object, uint32_t number, uint8_t connection_id, uint8_t status);
	void* status_callback_object;
	int (*data_callback)(void* object, uint32_t number, uint8_t connection_id, const uint8_t* data, uint16_t length);
	void* data_callback_object;
	int (*oob_data_callback)(void* object, const uint8_t* public_key, const uint8_t* data, uint16_t length);
	void* oob_data_callback_object;

	int (*onion_callback)(void* object, const uint8_t* data, uint16_t length);
	void* onion_callback_object;

	/* Can be used by user. */
	void* custom_object;
	uint32_t custom_uint;
} TCP_Client_Connection;



class TCP_client : public QObject
{
	Q_OBJECT

public:
	TCP_client(QObject *parent);
	~TCP_client();
};


int send_data(TCP_Client_Connection* con, uint8_t con_id, const uint8_t* data, uint16_t length);

int send_oob_packet(TCP_Client_Connection* con, const uint8_t* public_key, const uint8_t* data, uint16_t length);
int send_disconnect_request(TCP_Client_Connection* con, uint8_t con_id);
void kill_TCP_connection(TCP_Client_Connection* TCP_connection);
int send_onion_request(TCP_Client_Connection* con, const uint8_t* data, uint16_t length);