#pragma once

#include <QObject>
#include "tcp_client.h"
#include "cryptocore.h"
#include "dht.h"

#define TCP_CONN_NONE 0
#define TCP_CONN_VALID 1

/* NOTE: only used by TCP_con */
#define TCP_CONN_CONNECTED 2

/* Connection is not connected but can be quickly reconnected in case it is needed. */
#define TCP_CONN_SLEEPING 3

#define TCP_CONNECTIONS_STATUS_NONE 0
#define TCP_CONNECTIONS_STATUS_REGISTERED 1
#define TCP_CONNECTIONS_STATUS_ONLINE 2

#define MAX_FRIEND_TCP_CONNECTIONS 6

/* Time until connection to friend gets killed (if it doesn't get locked withing that time) */
#define TCP_CONNECTION_ANNOUNCE_TIMEOUT (TCP_CONNECTION_TIMEOUT)

/* The amount of recommended connections for each friend
   NOTE: Must be at most (MAX_FRIEND_TCP_CONNECTIONS / 2) */
#define RECOMMENDED_FRIEND_TCP_CONNECTIONS (MAX_FRIEND_TCP_CONNECTIONS / 2)

   /* Number of TCP connections used for onion purposes. */
#define NUM_ONION_TCP_CONNECTIONS RECOMMENDED_FRIEND_TCP_CONNECTIONS



class DHT;

typedef struct {
	uint8_t status;
	uint8_t public_key[crypto_box_PUBLICKEYBYTES]; /* The dht public key of the peer */

	struct {
		uint32_t tcp_connection;
		unsigned int status;
		unsigned int connection_id;
	} connections[MAX_FRIEND_TCP_CONNECTIONS];

	int id; /* id used in callbacks. */
} TCP_Connection_to;

typedef struct {
	uint8_t status;
	TCP_Client_Connection* connection;
	uint64_t connected_time;
	uint32_t lock_count;
	uint32_t sleep_count;
	bool onion;

	/* Only used when connection is sleeping. */
	IP_Port ip_port;
	uint8_t relay_pk[crypto_box_PUBLICKEYBYTES];
	bool unsleep; /* set to 1 to unsleep connection. */
} TCP_con;

class TCP_Connections : public QObject
{
	Q_OBJECT

public:
	TCP_Connections(QObject *parent=nullptr);
	~TCP_Connections();

	int init(const uint8_t* secret_key, TCP_Proxy_Info* proxy_info);
	void set_packet_tcp_connection_callback(int (*tcp_data_callback)(void* object, int id, const uint8_t* data, uint16_t length), void* object);
	void set_oob_packet_tcp_connection_callback(int (*tcp_oob_callback)(void* object, const uint8_t* public_key, unsigned int tcp_connections_number, const uint8_t* data, uint16_t length), void* object);
	//////////////////////////////////////////////////////

	std::shared_ptr<DHT> m_dht{ nullptr };

	uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
	uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];

	TCP_Connection_to* connections;
	uint32_t connections_length; /* Length of connections array. */

	TCP_con* tcp_connections;
	uint32_t tcp_connections_length; /* Length of tcp_connections array. */

	int (*tcp_data_callback)(void* object, int id, const uint8_t* data, uint16_t length);
	void* tcp_data_callback_object;

	int (*tcp_oob_callback)(void* object, const uint8_t* public_key, unsigned int tcp_connections_number,
		const uint8_t* data, uint16_t length);
	void* tcp_oob_callback_object;

	int (*tcp_onion_callback)(void* object, const uint8_t* data, uint16_t length);
	void* tcp_onion_callback_object;

	TCP_Proxy_Info proxy_info;

	bool onion_status;
	uint16_t onion_num_conns;
};


int send_packet_tcp_connection(TCP_Connections* tcp_c, int connections_number, const uint8_t* packet, uint16_t length);
unsigned int tcp_connection_to_online_tcp_relays(TCP_Connections* tcp_c, int connections_number);
int tcp_send_oob_packet(TCP_Connections* tcp_c, unsigned int tcp_connections_number, const uint8_t* public_key, const uint8_t* packet, uint16_t length);
int kill_tcp_connection_to(TCP_Connections* tcp_c, int connections_number);
void kill_tcp_connections(TCP_Connections* tcp_c);

int get_random_tcp_onion_conn_number(TCP_Connections* tcp_c);
int set_tcp_onion_status(TCP_Connections* tcp_c, bool status);
void set_onion_packet_tcp_connection_callback(TCP_Connections* tcp_c, int (*tcp_onion_callback)(void* object, const uint8_t* data, uint16_t length), void* object);
int tcp_send_onion_request(TCP_Connections* tcp_c, unsigned int tcp_connections_number, const uint8_t* data, uint16_t length);

unsigned int tcp_copy_connected_relays(TCP_Connections* tcp_c, Node_format* tcp_relays, uint16_t max_num);