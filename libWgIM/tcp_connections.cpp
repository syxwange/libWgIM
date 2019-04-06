#include "tcp_connections.h"


/* Set the size of the array to num.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
#define realloc_tox_array(array, element_size, num, temp_pointer) (num ? (temp_pointer = (TCP_Connection_to*)realloc(array, ((num) * (element_size))), temp_pointer ? (array = temp_pointer, 0) : (-1) ) : (free(array), array = NULL, 0))



TCP_Connections::TCP_Connections(QObject *parent)	: QObject(parent)
{
}

TCP_Connections::~TCP_Connections()
{
}

/* Returns a new TCP_Connections object associated with the secret_key.
 *
 * In order for others to connect to this instance new_tcp_connection_to() must be called with the
 * public_key associated with secret_key.
 *
 * Returns NULL on failure.
 */
int TCP_Connections::init(const uint8_t* secret_key, TCP_Proxy_Info* proxy_info)
{
	if (secret_key == NULL)
		return 1;
	memcpy(self_secret_key, secret_key, crypto_box_SECRETKEYBYTES);
	crypto_scalarmult_curve25519_base(self_public_key,self_secret_key);
	this->proxy_info = *proxy_info;
	return 0;
}



/* Set the callback for TCP data packets.
 */
void TCP_Connections::set_packet_tcp_connection_callback(int (*tcp_data_callback)(void* object, int id,	const uint8_t* data, uint16_t length), void* object)
{
	tcp_data_callback = tcp_data_callback;
	tcp_data_callback_object = object;
}


/* Set the callback for TCP onion packets.
 */
void TCP_Connections::set_oob_packet_tcp_connection_callback(int (*tcp_oob_callback)(void* object,	const uint8_t* public_key, unsigned int tcp_connections_number,
	const uint8_t* data, uint16_t length), void* object)
{
	tcp_oob_callback = tcp_oob_callback;
	tcp_oob_callback_object = object;
}


/* return 1 if the connections_number is not valid.
 * return 0 if the connections_number is valid.
 */
static bool connections_number_not_valid(const TCP_Connections* tcp_c, int connections_number)
{
	if ((unsigned int)connections_number >= tcp_c->connections_length)
		return 1;

	if (tcp_c->connections == NULL)
		return 1;

	if (tcp_c->connections[connections_number].status == TCP_CONN_NONE)
		return 1;

	return 0;
}


static TCP_Connection_to* get_connection(const TCP_Connections* tcp_c, int connections_number)
{
	if (connections_number_not_valid(tcp_c, connections_number))
		return 0;

	return &tcp_c->connections[connections_number];
}


/* return 1 if the tcp_connections_number is not valid.
 * return 0 if the tcp_connections_number is valid.
 */
static bool tcp_connections_number_not_valid(const TCP_Connections* tcp_c, int tcp_connections_number)
{
	if ((unsigned int)tcp_connections_number >= tcp_c->tcp_connections_length)
		return 1;

	if (tcp_c->tcp_connections == NULL)
		return 1;

	if (tcp_c->tcp_connections[tcp_connections_number].status == TCP_CONN_NONE)
		return 1;

	return 0;
}

static TCP_con* get_tcp_connection(const TCP_Connections* tcp_c, int tcp_connections_number)
{
	if (tcp_connections_number_not_valid(tcp_c, tcp_connections_number))
		return 0;

	return &tcp_c->tcp_connections[tcp_connections_number];
}

/* Send a packet to the TCP connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_packet_tcp_connection(TCP_Connections* tcp_c, int connections_number, const uint8_t* packet, uint16_t length)
{
	TCP_Connection_to* con_to = get_connection(tcp_c, connections_number);

	if (!con_to) {
		return -1;
	}

	//TODO: detect and kill bad relays.
	//TODO: thread safety?
	unsigned int i;
	int ret = -1;

	bool limit_reached = 0;

	for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
		uint32_t tcp_con_num = con_to->connections[i].tcp_connection;
		uint8_t status = con_to->connections[i].status;
		uint8_t connection_id = con_to->connections[i].connection_id;

		if (tcp_con_num && status == TCP_CONNECTIONS_STATUS_ONLINE) {
			tcp_con_num -= 1;
			TCP_con* tcp_con = get_tcp_connection(tcp_c, tcp_con_num);

			if (!tcp_con) {
				continue;
			}

			ret = send_data(tcp_con->connection, connection_id, packet, length);

			if (ret == 0) {
				limit_reached = 1;
			}

			if (ret == 1) {
				break;
			}
		}
	}

	if (ret == 1) {
		return 0;
	}
	else if (!limit_reached) {
		ret = 0;

		/* Send oob packets to all relays tied to the connection. */
		for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
			uint32_t tcp_con_num = con_to->connections[i].tcp_connection;
			uint8_t status = con_to->connections[i].status;

			if (tcp_con_num && status == TCP_CONNECTIONS_STATUS_REGISTERED) {
				tcp_con_num -= 1;
				TCP_con* tcp_con = get_tcp_connection(tcp_c, tcp_con_num);

				if (!tcp_con) {
					continue;
				}

				if (send_oob_packet(tcp_con->connection, con_to->public_key, packet, length) == 1) {
					ret += 1;
				}
			}
		}

		if (ret >= 1) {
			return 0;
		}
		else {
			return -1;
		}
	}
	else {
		return -1;
	}
}

/* return number of online connections on success.
 * return -1 on failure.
 */
static unsigned int online_tcp_connection_from_conn(TCP_Connection_to* con_to)
{
	unsigned int i, count = 0;

	for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
		if (con_to->connections[i].tcp_connection) {
			if (con_to->connections[i].status == TCP_CONNECTIONS_STATUS_ONLINE) {
				++count;
			}
		}
	}

	return count;
}

/* return number of online tcp relays tied to the connection on success.
 * return 0 on failure.
 */
unsigned int tcp_connection_to_online_tcp_relays(TCP_Connections* tcp_c, int connections_number)
{
	TCP_Connection_to* con_to = get_connection(tcp_c, connections_number);

	if (!con_to)
		return 0;

	return online_tcp_connection_from_conn(con_to);
}

/* Send an oob packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_oob_packet(TCP_Connections* tcp_c, unsigned int tcp_connections_number, const uint8_t* public_key,	const uint8_t* packet, uint16_t length)
{
	TCP_con* tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

	if (!tcp_con)
		return -1;

	if (tcp_con->status != TCP_CONN_CONNECTED)
		return -1;

	int ret = send_oob_packet(tcp_con->connection, public_key, packet, length);

	if (ret == 1)
		return 0;

	return -1;
}

/* Wipe a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_connection(TCP_Connections* tcp_c, int connections_number)
{
	if (connections_number_not_valid(tcp_c, connections_number))
		return -1;

	uint32_t i;
	memset(&(tcp_c->connections[connections_number]), 0, sizeof(TCP_Connection_to));

	for (i = tcp_c->connections_length; i != 0; --i) {
		if (tcp_c->connections[i - 1].status != TCP_CONN_NONE)
			break;
	}

	if (tcp_c->connections_length != i) {
		tcp_c->connections_length = i;
		TCP_Connection_to* temp_pointer;
		realloc_tox_array(tcp_c->connections, sizeof(TCP_Connection_to), tcp_c->connections_length, temp_pointer);
	}

	return 0;
}


/* return 0 on success.
 * return -1 on failure.
 */
int kill_tcp_connection_to(TCP_Connections* tcp_c, int connections_number)
{
	TCP_Connection_to* con_to = get_connection(tcp_c, connections_number);

	if (!con_to)
		return -1;

	unsigned int i;

	for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
		if (con_to->connections[i].tcp_connection) {
			unsigned int tcp_connections_number = con_to->connections[i].tcp_connection - 1;
			TCP_con* tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

			if (!tcp_con)
				continue;

			if (tcp_con->status == TCP_CONN_CONNECTED) {
				send_disconnect_request(tcp_con->connection, con_to->connections[i].connection_id);
			}

			if (con_to->connections[i].status == TCP_CONNECTIONS_STATUS_ONLINE) {
				--tcp_con->lock_count;

				if (con_to->status == TCP_CONN_SLEEPING) {
					--tcp_con->sleep_count;
				}
			}
		}
	}

	return wipe_connection(tcp_c, connections_number);
}

void kill_tcp_connections(TCP_Connections* tcp_c)
{
	unsigned int i;

	for (i = 0; i < tcp_c->tcp_connections_length; ++i) {
		kill_TCP_connection(tcp_c->tcp_connections[i].connection);
	}

	free(tcp_c->tcp_connections);
	free(tcp_c->connections);
	free(tcp_c);
}


/* Return a random TCP connection number for use in send_tcp_onion_request.
 *
 * TODO: This number is just the index of an array that the elements can
 * change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int get_random_tcp_onion_conn_number(TCP_Connections* tcp_c)
{
	unsigned int i, r = rand();

	for (i = 0; i < tcp_c->tcp_connections_length; ++i) {
		unsigned int index = ((i + r) % tcp_c->tcp_connections_length);

		if (tcp_c->tcp_connections[index].onion && tcp_c->tcp_connections[index].status == TCP_CONN_CONNECTED) {
			return index;
		}
	}

	return -1;
}


/* Set if we want TCP_connection to allocate some connection for onion use.
 *
 * If status is 1, allocate some connections. if status is 0, don't.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int set_tcp_onion_status(TCP_Connections* tcp_c, bool status)
{
	if (tcp_c->onion_status == status)
		return -1;

	if (status) {
		unsigned int i;

		for (i = 0; i < tcp_c->tcp_connections_length; ++i) {
			TCP_con* tcp_con = get_tcp_connection(tcp_c, i);

			if (tcp_con) {
				if (tcp_con->status == TCP_CONN_CONNECTED && !tcp_con->onion) {
					++tcp_c->onion_num_conns;
					tcp_con->onion = 1;
				}
			}

			if (tcp_c->onion_num_conns >= NUM_ONION_TCP_CONNECTIONS)
				break;
		}

		if (tcp_c->onion_num_conns < NUM_ONION_TCP_CONNECTIONS) {
			unsigned int wakeup = NUM_ONION_TCP_CONNECTIONS - tcp_c->onion_num_conns;

			for (i = 0; i < tcp_c->tcp_connections_length; ++i) {
				TCP_con* tcp_con = get_tcp_connection(tcp_c, i);

				if (tcp_con) {
					if (tcp_con->status == TCP_CONN_SLEEPING) {
						tcp_con->unsleep = 1;
					}
				}

				if (!wakeup)
					break;
			}
		}

		tcp_c->onion_status = 1;
	}
	else {
		unsigned int i;

		for (i = 0; i < tcp_c->tcp_connections_length; ++i) {
			TCP_con* tcp_con = get_tcp_connection(tcp_c, i);

			if (tcp_con) {
				if (tcp_con->onion) {
					--tcp_c->onion_num_conns;
					tcp_con->onion = 0;
				}
			}
		}

		tcp_c->onion_status = 0;
	}

	return 0;
}

/* Set the callback for TCP oob data packets.
 */
void set_onion_packet_tcp_connection_callback(TCP_Connections* tcp_c, int (*tcp_onion_callback)(void* object,const uint8_t* data, uint16_t length), void* object)
{
	tcp_c->tcp_onion_callback = tcp_onion_callback;
	tcp_c->tcp_onion_callback_object = object;
}

/* Send an onion packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_onion_request(TCP_Connections* tcp_c, unsigned int tcp_connections_number, const uint8_t* data,	uint16_t length)
{
	if (tcp_connections_number >= tcp_c->tcp_connections_length) {
		return -1;
	}

	if (tcp_c->tcp_connections[tcp_connections_number].status == TCP_CONN_CONNECTED) {
		int ret = send_onion_request(tcp_c->tcp_connections[tcp_connections_number].connection, data, length);

		if (ret == 1)
			return 0;
	}

	return -1;
}

/* Copy a maximum of max_num TCP relays we are connected to to tcp_relays.
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
unsigned int tcp_copy_connected_relays(TCP_Connections* tcp_c, Node_format* tcp_relays, uint16_t max_num)
{
	unsigned int i, copied = 0, r = rand();

	for (i = 0; (i < tcp_c->tcp_connections_length) && (copied < max_num); ++i) {
		TCP_con* tcp_con = get_tcp_connection(tcp_c, (i + r) % tcp_c->tcp_connections_length);

		if (!tcp_con) {
			continue;
		}

		if (tcp_con->status == TCP_CONN_CONNECTED) {
			memcpy(tcp_relays[copied].public_key, tcp_con->connection->public_key, crypto_box_PUBLICKEYBYTES);
			tcp_relays[copied].ip_port = tcp_con->connection->ip_port;

			if (tcp_relays[copied].ip_port.ip.family == AF_INET) {
				tcp_relays[copied].ip_port.ip.family = TCP_INET;
			}
			else if (tcp_relays[copied].ip_port.ip.family == AF_INET6) {
				tcp_relays[copied].ip_port.ip.family = TCP_INET6;
			}

			++copied;
		}
	}

	return copied;
}
