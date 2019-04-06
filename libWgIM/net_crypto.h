#pragma once

#include <QObject>
#include "tcp_connections.h"
#include <pthread.h>
#include "utiliy.h"

class DHT;

#define CRYPTO_CONN_NO_CONNECTION 0
#define CRYPTO_CONN_COOKIE_REQUESTING 1 //send cookie request packets
#define CRYPTO_CONN_HANDSHAKE_SENT 2 //send handshake packets
#define CRYPTO_CONN_NOT_CONFIRMED 3 //send handshake packets, we have received one from the other
#define CRYPTO_CONN_ESTABLISHED 4

/* Maximum size of receiving and sending packet buffers. */
#define CRYPTO_PACKET_BUFFER_SIZE 32768 /* Must be a power of 2 */

/* Minimum packet rate per second. */
#define CRYPTO_PACKET_MIN_RATE 4.0

/* Minimum packet queue max length. */
#define CRYPTO_MIN_QUEUE_LENGTH 64

/* Maximum total size of packets that net_crypto sends. */
#define MAX_CRYPTO_PACKET_SIZE 1400

#define CRYPTO_DATA_PACKET_MIN_SIZE (1 + sizeof(uint16_t) + (sizeof(uint32_t) + sizeof(uint32_t)) + crypto_box_MACBYTES)

/* Max size of data in packets */
#define MAX_CRYPTO_DATA_SIZE (MAX_CRYPTO_PACKET_SIZE - CRYPTO_DATA_PACKET_MIN_SIZE)

/* Interval in ms between sending cookie request/handshake packets. */
#define CRYPTO_SEND_PACKET_INTERVAL 1000

/* The maximum number of times we try to send the cookie request and handshake
   before giving up. */
#define MAX_NUM_SENDPACKET_TRIES 8

   /* The timeout of no received UDP packets before the direct UDP connection is considered dead. */
#define UDP_DIRECT_TIMEOUT ((MAX_NUM_SENDPACKET_TRIES * CRYPTO_SEND_PACKET_INTERVAL) / 1000)

#define PACKET_ID_PADDING 0 /* Denotes padding */
#define PACKET_ID_REQUEST 1 /* Used to request unreceived packets */
#define PACKET_ID_KILL    2 /* Used to kill connection */

/* Packet ids 0 to CRYPTO_RESERVED_PACKETS - 1 are reserved for use by net_crypto. */
#define CRYPTO_RESERVED_PACKETS 16

#define MAX_TCP_CONNECTIONS 64
#define MAX_TCP_RELAYS_PEER 4

/* All packets starting with a byte in this range are considered lossy packets. */
#define PACKET_ID_LOSSY_RANGE_START 192
#define PACKET_ID_LOSSY_RANGE_SIZE 63

#define CRYPTO_MAX_PADDING 8 /* All packets will be padded a number of bytes based on this number. */

/* Base current transfer speed on last CONGESTION_QUEUE_ARRAY_SIZE number of points taken
   at the dT defined in net_crypto.c */
#define CONGESTION_QUEUE_ARRAY_SIZE 12
#define CONGESTION_LAST_SENT_ARRAY_SIZE (CONGESTION_QUEUE_ARRAY_SIZE * 2)

   /* Default connection ping in ms. */
#define DEFAULT_PING_CONNECTION 1000
#define DEFAULT_TCP_PING_CONNECTION 500

typedef struct {
	uint64_t sent_time;
	uint16_t length;
	uint8_t data[MAX_CRYPTO_DATA_SIZE];
} Packet_Data;

typedef struct {
	Packet_Data* buffer[CRYPTO_PACKET_BUFFER_SIZE];
	uint32_t  buffer_start;
	uint32_t  buffer_end; /* packet numbers in array: {buffer_start, buffer_end) */
} Packets_Array;

typedef struct {
	uint8_t public_key[crypto_box_PUBLICKEYBYTES]; /* The real public key of the peer. */
	uint8_t recv_nonce[crypto_box_NONCEBYTES]; /* Nonce of received packets. */
	uint8_t sent_nonce[crypto_box_NONCEBYTES]; /* Nonce of sent packets. */
	uint8_t sessionpublic_key[crypto_box_PUBLICKEYBYTES]; /* Our public key for this session. */
	uint8_t sessionsecret_key[crypto_box_SECRETKEYBYTES]; /* Our private key for this session. */
	uint8_t peersessionpublic_key[crypto_box_PUBLICKEYBYTES]; /* The public key of the peer. */
	uint8_t shared_key[crypto_box_BEFORENMBYTES]; /* The precomputed shared key from encrypt_precompute. */
	uint8_t status; /* 0 if no connection, 1 we are sending cookie request packets,
					 * 2 if we are sending handshake packets
					 * 3 if connection is not confirmed yet (we have received a handshake but no data packets yet),
					 * 4 if the connection is established.
					 */
	uint64_t cookie_request_number; /* number used in the cookie request packets for this connection */
	uint8_t dht_public_key[crypto_box_PUBLICKEYBYTES]; /* The dht public key of the peer */

	uint8_t* temp_packet; /* Where the cookie request/handshake packet is stored while it is being sent. */
	uint16_t temp_packet_length;
	uint64_t temp_packet_sent_time; /* The time at which the last temp_packet was sent in ms. */
	uint32_t temp_packet_num_sent;

	IP_Port ip_portv4; /* The ip and port to contact this guy directly.*/
	IP_Port ip_portv6;
	uint64_t direct_lastrecv_timev4; /* The Time at which we last received a direct packet in ms. */
	uint64_t direct_lastrecv_timev6;

	uint64_t last_tcp_sent; /* Time the last TCP packet was sent. */

	Packets_Array send_array;
	Packets_Array recv_array;

	int (*connection_status_callback)(void* object, int id, uint8_t status);
	void* connection_status_callback_object;
	int connection_status_callback_id;

	int (*connection_data_callback)(void* object, int id, uint8_t* data, uint16_t length);
	void* connection_data_callback_object;
	int connection_data_callback_id;

	int (*connection_lossy_data_callback)(void* object, int id, const uint8_t* data, uint16_t length);
	void* connection_lossy_data_callback_object;
	int connection_lossy_data_callback_id;

	uint64_t last_request_packet_sent;
	uint64_t direct_send_attempt_time;

	uint32_t packet_counter;
	double packet_recv_rate;
	uint64_t packet_counter_set;

	double packet_send_rate;
	uint32_t packets_left;
	uint64_t last_packets_left_set;
	double last_packets_left_rem;

	double packet_send_rate_requested;
	uint32_t packets_left_requested;
	uint64_t last_packets_left_requested_set;
	double last_packets_left_requested_rem;

	uint32_t last_sendqueue_size[CONGESTION_QUEUE_ARRAY_SIZE], last_sendqueue_counter;
	long signed int last_num_packets_sent[CONGESTION_LAST_SENT_ARRAY_SIZE],
		last_num_packets_resent[CONGESTION_LAST_SENT_ARRAY_SIZE];
	uint32_t packets_sent, packets_resent;
	uint64_t last_congestion_event;
	uint64_t rtt_time;

	/* TCP_connection connection_number */
	unsigned int connection_number_tcp;

	uint8_t maximum_speed_reached;

	pthread_mutex_t mutex;

	void (*dht_pk_callback)(void* data, int32_t number, const uint8_t* dht_public_key);
	void* dht_pk_callback_object;
	uint32_t dht_pk_callback_number;
} Crypto_Connection;

typedef struct {
	IP_Port source;
	uint8_t public_key[crypto_box_PUBLICKEYBYTES]; /* The real public key of the peer. */
	uint8_t dht_public_key[crypto_box_PUBLICKEYBYTES]; /* The dht public key of the peer. */
	uint8_t recv_nonce[crypto_box_NONCEBYTES]; /* Nonce of received packets. */
	uint8_t peersessionpublic_key[crypto_box_PUBLICKEYBYTES]; /* The public key of the peer. */
	uint8_t* cookie;
	uint8_t cookie_length;
} New_Connection;

class Net_Crypto : public QObject
{
	Q_OBJECT

public:
	Net_Crypto(QObject *parent=nullptr);
	~Net_Crypto();

	int init(std::shared_ptr<DHT> dht, TCP_Proxy_Info* proxy_info);
	void new_keys();
//////////////////////////////////////////////////////////////////////////////////
	    
	std::shared_ptr<DHT> m_dht{nullptr};
	TCP_Connections* tcp_c=nullptr;

	Crypto_Connection* crypto_connections;
	pthread_mutex_t tcp_mutex;

	pthread_mutex_t connections_mutex;
	unsigned int connection_use_counter;

	uint32_t crypto_connections_length; /* Length of connections array. */

	/* Our public and secret keys. */
	uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
	uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];

	/* The secret key used for cookies */
	uint8_t secret_symmetric_key[crypto_box_KEYBYTES];

	int (*new_connection_callback)(void* object, New_Connection* n_c);
	void* new_connection_callback_object;

	/* The current optimal sleep time */
	uint32_t current_sleep_time;

	BS_LIST ip_port_list;
};

int get_random_tcp_con_number(Net_Crypto* c);

int send_tcp_onion_request(Net_Crypto* c, unsigned int tcp_connections_number, const uint8_t* data, uint16_t length);

unsigned int copy_connected_tcp_relays(Net_Crypto* c, Node_format* tcp_relays, uint16_t num);
