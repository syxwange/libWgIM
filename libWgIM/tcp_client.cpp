#include "tcp_client.h"
#include "cryptocore.h"

TCP_client::TCP_client(QObject *parent)	: QObject(parent)
{
}

TCP_client::~TCP_client()
{
}

/* return 0 if pending data was sent completely
 * return -1 if it wasn't
 */
static int send_pending_data_nonpriority(TCP_Client_Connection* con)
{
	if (con->last_packet_length == 0) {
		return 0;
	}

	uint16_t left = con->last_packet_length - con->last_packet_sent;
	int len = send(con->sock, (char *)con->last_packet + con->last_packet_sent, left, MSG_NOSIGNAL);

	if (len <= 0)
		return -1;

	if (len == left) {
		con->last_packet_length = 0;
		con->last_packet_sent = 0;
		return 0;
	}

	con->last_packet_sent += len;
	return -1;
}


void wipe_priority_list(TCP_Priority_List* p)
{
	while (p) {
		TCP_Priority_List* pp = p;
		p = p->next;
		free(pp);
	}
}

/* return 0 if pending data was sent completely
 * return -1 if it wasn't
 */
static int send_pending_data(TCP_Client_Connection* con)
{
	/* finish sending current non-priority packet */
	if (send_pending_data_nonpriority(con) == -1) {
		return -1;
	}

	TCP_Priority_List* p = con->priority_queue_start;

	while (p) {
		uint16_t left = p->size - p->sent;
		int len = send(con->sock, (char *)p->data + p->sent, left, MSG_NOSIGNAL);

		if (len != left) {
			if (len > 0) {
				p->sent += len;
			}

			break;
		}

		TCP_Priority_List* pp = p;
		p = p->next;
		free(pp);
	}

	con->priority_queue_start = p;

	if (!p) {
		con->priority_queue_end = NULL;
		return 0;
	}

	return -1;
}


/* return 0 on failure (only if malloc fails)
 * return 1 on success
 */
static bool add_priority(TCP_Client_Connection* con, const uint8_t* packet, uint16_t size, uint16_t sent)
{
	TCP_Priority_List* p = con->priority_queue_end, * new1;
	new1 =(TCP_Priority_List*) malloc(sizeof(TCP_Priority_List) + size);

	if (!new1) {
		return 0;
	}

	new1->next = NULL;
	new1->size = size;
	new1->sent = sent;
	memcpy(new1->data, packet, size);

	if (p) {
		p->next = new1;
	}
	else {
		con->priority_queue_start = new1;
	}

	con->priority_queue_end = new1;
	return 1;
}


/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int write_packet_TCP_secure_connection(TCP_Client_Connection* con, const uint8_t* data, uint16_t length,	bool priority)
{
	if (length + crypto_box_MACBYTES > MAX_PACKET_SIZE)
		return -1;

	bool sendpriority = 1;

	if (send_pending_data(con) == -1) {
		if (priority) {
			sendpriority = 0;
		}
		else {
			return 0;
		}
	}

	uint8_t* packet = new uint8_t[sizeof(uint16_t) + length + crypto_box_MACBYTES];

	uint16_t c_length = htons(length + crypto_box_MACBYTES);
	memcpy(packet, &c_length, sizeof(uint16_t));
	int len =CryptoCore::encryptDataSymmetric(con->shared_key, con->sent_nonce, data, length, packet + sizeof(uint16_t));

	if ((unsigned int)len != (sizeof(packet) - sizeof(uint16_t)))
		return -1;

	if (priority) {
		len = sendpriority ? send(con->sock, (char *)packet, sizeof(packet), MSG_NOSIGNAL) : 0;

		if (len <= 0) {
			len = 0;
		}

		 increment_nonce(con->sent_nonce);

		if ((unsigned int)len == sizeof(packet)) {
			return 1;
		}

		return add_priority(con, packet, sizeof(packet), len);
	}

	len = send(con->sock, (char *)packet, sizeof(packet), MSG_NOSIGNAL);

	if (len <= 0)
		return 0;

	increment_nonce(con->sent_nonce);

	if ((unsigned int)len == sizeof(packet))
		return 1;

	memcpy(con->last_packet, packet, sizeof(packet));
	con->last_packet_length = sizeof(packet);
	con->last_packet_sent = len;
	return 1;
}


/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int send_ping_response(TCP_Client_Connection* con)
{
	if (!con->ping_response_id)
		return 1;

	uint8_t packet[1 + sizeof(uint64_t)];
	packet[0] = TCP_PACKET_PONG;
	memcpy(packet + 1, &con->ping_response_id, sizeof(uint64_t));
	int ret;

	if ((ret = write_packet_TCP_secure_connection(con, packet, sizeof(packet), 1)) == 1) {
		con->ping_response_id = 0;
	}

	return ret;
}



/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int send_ping_request(TCP_Client_Connection* con)
{
	if (!con->ping_request_id)
		return 1;

	uint8_t packet[1 + sizeof(uint64_t)];
	packet[0] = TCP_PACKET_PING;
	memcpy(packet + 1, &con->ping_request_id, sizeof(uint64_t));
	int ret;

	if ((ret = write_packet_TCP_secure_connection(con, packet, sizeof(packet), 1)) == 1) {
		con->ping_request_id = 0;
	}

	return ret;
}


/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure.
 */
int send_data(TCP_Client_Connection* con, uint8_t con_id, const uint8_t* data, uint16_t length)
{
	if (con_id >= NUM_CLIENT_CONNECTIONS)
		return -1;

	if (con->connections[con_id].status != 2)
		return -1;

	if (send_ping_response(con) == 0 || send_ping_request(con) == 0)
		return 0;

	uint8_t *packet=new uint8_t[1 + length];
	packet[0] = con_id + NUM_RESERVED_PORTS;
	memcpy(packet + 1, data, length);
	 auto r =write_packet_TCP_secure_connection(con, packet, sizeof(packet), 0);
	 delete[] packet;
	 return r;
}


/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure.
 */
int send_oob_packet(TCP_Client_Connection* con, const uint8_t* public_key, const uint8_t* data, uint16_t length)
{
	if (length == 0 || length > TCP_MAX_OOB_DATA_LENGTH)
		return -1;

	uint8_t *packet=new uint8_t[1 + crypto_box_PUBLICKEYBYTES + length];
	packet[0] = TCP_PACKET_OOB_SEND;
	memcpy(packet + 1, public_key, crypto_box_PUBLICKEYBYTES);
	memcpy(packet + 1 + crypto_box_PUBLICKEYBYTES, data, length);
	auto r = write_packet_TCP_secure_connection(con, packet, sizeof(packet), 0);
	delete[]packet;
	return r;
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int send_disconnect_notification(TCP_Client_Connection* con, uint8_t id)
{
	uint8_t packet[1 + 1];
	packet[0] = TCP_PACKET_DISCONNECT_NOTIFICATION;
	packet[1] = id;
	return write_packet_TCP_secure_connection(con, packet, sizeof(packet), 1);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int send_disconnect_request(TCP_Client_Connection* con, uint8_t con_id)
{
	if (con_id >= NUM_CLIENT_CONNECTIONS)
		return -1;

	con->connections[con_id].status = 0;
	con->connections[con_id].number = 0;
	return send_disconnect_notification(con, con_id + NUM_RESERVED_PORTS);
}

/* Kill the TCP connection
 */
void kill_TCP_connection(TCP_Client_Connection* TCP_connection)
{
	if (TCP_connection == NULL)
		return;

	wipe_priority_list(TCP_connection->priority_queue_start);
	kill_sock(TCP_connection->sock);
	sodium_memzero(TCP_connection, sizeof(TCP_Client_Connection));
	free(TCP_connection);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int send_onion_request(TCP_Client_Connection* con, const uint8_t* data, uint16_t length)
{
	uint8_t *packet=new uint8_t[1 + length];
	packet[0] = TCP_PACKET_ONION_REQUEST;
	memcpy(packet + 1, data, length);
	return write_packet_TCP_secure_connection(con, packet, sizeof(packet), 0);
}