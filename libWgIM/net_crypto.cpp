#include "net_crypto.h"
#include "dht.h"

/* cookie timeout in seconds */
#define COOKIE_TIMEOUT 15
#define COOKIE_DATA_LENGTH (crypto_box_PUBLICKEYBYTES * 2)
#define COOKIE_CONTENTS_LENGTH (sizeof(uint64_t) + COOKIE_DATA_LENGTH)
#define COOKIE_LENGTH (crypto_box_NONCEBYTES + COOKIE_CONTENTS_LENGTH + crypto_box_MACBYTES)

#define COOKIE_REQUEST_PLAIN_LENGTH (COOKIE_DATA_LENGTH + sizeof(uint64_t))
#define COOKIE_REQUEST_LENGTH (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + COOKIE_REQUEST_PLAIN_LENGTH + crypto_box_MACBYTES)
#define COOKIE_RESPONSE_LENGTH (1 + crypto_box_NONCEBYTES + COOKIE_LENGTH + sizeof(uint64_t) + crypto_box_MACBYTES)
#define HANDSHAKE_PACKET_LENGTH (1 + COOKIE_LENGTH + crypto_box_NONCEBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES + COOKIE_LENGTH + crypto_box_MACBYTES)

#define MAX_DATA_DATA_PACKET_SIZE (MAX_CRYPTO_PACKET_SIZE - (1 + sizeof(uint16_t) + crypto_box_MACBYTES))
#define DATA_NUM_THRESHOLD 21845

#define CRYPTO_MIN_PACKET_SIZE (1 + sizeof(uint16_t) + crypto_box_MACBYTES)

static uint8_t crypt_connection_id_not_valid(const Net_Crypto* c, int crypt_connection_id)
{
	if ((uint32_t)crypt_connection_id >= c->crypto_connections_length)
		return 1;

	if (c->crypto_connections == NULL)
		return 1;

	if (c->crypto_connections[crypt_connection_id].status == CRYPTO_CONN_NO_CONNECTION)
		return 1;

	return 0;
}

static Crypto_Connection* get_crypto_connection(const Net_Crypto* c, int crypt_connection_id)
{
	if (crypt_connection_id_not_valid(c, crypt_connection_id))
		return 0;

	return &c->crypto_connections[crypt_connection_id];
}

/* Handle the cookie request packet of length length.
 * Put what was in the request in request_plain (must be of size COOKIE_REQUEST_PLAIN_LENGTH)
 * Put the key used to decrypt the request into shared_key (of size crypto_box_BEFORENMBYTES) for use in the response.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_cookie_request(const Net_Crypto* c, uint8_t* request_plain, uint8_t* shared_key,	uint8_t* dht_public_key, const uint8_t* packet, uint16_t length)
{
	if (length != COOKIE_REQUEST_LENGTH)
		return -1;
	memcpy(dht_public_key, packet + 1, crypto_box_PUBLICKEYBYTES);
	c->m_dht->getSharedKeySent(shared_key, dht_public_key);
	int len =CryptoCore::decryptDataSymmetric(shared_key, packet + 1 + crypto_box_PUBLICKEYBYTES,
		packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, COOKIE_REQUEST_PLAIN_LENGTH + crypto_box_MACBYTES, request_plain);

	if (len != COOKIE_REQUEST_PLAIN_LENGTH)
		return -1;
	return 0;
}

/* Create cookie of length COOKIE_LENGTH from bytes of length COOKIE_DATA_LENGTH using encryption_key
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int create_cookie(uint8_t* cookie, const uint8_t* bytes, const uint8_t* encryption_key)
{
	uint8_t contents[COOKIE_CONTENTS_LENGTH];
	uint64_t temp_time = unix_time();
	memcpy(contents, &temp_time, sizeof(temp_time));
	memcpy(contents + sizeof(temp_time), bytes, COOKIE_DATA_LENGTH);
	 CryptoCore::newNonce(cookie);
	int len = CryptoCore::encryptDataSymmetric(encryption_key, cookie, contents, sizeof(contents), cookie + crypto_box_NONCEBYTES);

	if (len != COOKIE_LENGTH - crypto_box_NONCEBYTES)
		return -1;

	return 0;
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

/* Create a cookie response packet and put it in packet.
 * request_plain must be COOKIE_REQUEST_PLAIN_LENGTH bytes.
 * packet must be of size COOKIE_RESPONSE_LENGTH or bigger.
 *
 * return -1 on failure.
 * return COOKIE_RESPONSE_LENGTH on success.
 */
static int create_cookie_response(const Net_Crypto* c, uint8_t* packet, const uint8_t* request_plain,
	const uint8_t* shared_key, const uint8_t* dht_public_key)
{
	uint8_t cookie_plain[COOKIE_DATA_LENGTH];
	memcpy(cookie_plain, request_plain, crypto_box_PUBLICKEYBYTES);
	memcpy(cookie_plain + crypto_box_PUBLICKEYBYTES, dht_public_key, crypto_box_PUBLICKEYBYTES);
	uint8_t plain[COOKIE_LENGTH + sizeof(uint64_t)];

	if (create_cookie(plain, cookie_plain, c->secret_symmetric_key) != 0)
		return -1;

	memcpy(plain + COOKIE_LENGTH, request_plain + COOKIE_DATA_LENGTH, sizeof(uint64_t));
	packet[0] = NET_PACKET_COOKIE_RESPONSE;
	CryptoCore::newNonce(packet + 1);
	int len = CryptoCore::encryptDataSymmetric(shared_key, packet + 1, plain, sizeof(plain), packet + 1 + crypto_box_NONCEBYTES);

	if (len != COOKIE_RESPONSE_LENGTH - (1 + crypto_box_NONCEBYTES))
		return -1;

	return COOKIE_RESPONSE_LENGTH;
}



/* Handle the cookie request packet (for TCP)
 */
static int tcp_handle_cookie_request(Net_Crypto* c, int connections_number, const uint8_t* packet, uint16_t length)
{
	uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
	uint8_t shared_key[crypto_box_BEFORENMBYTES];
	uint8_t dht_public_key[crypto_box_PUBLICKEYBYTES];

	if (handle_cookie_request(c, request_plain, shared_key, dht_public_key, packet, length) != 0)
		return -1;

	uint8_t data[COOKIE_RESPONSE_LENGTH];

	if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data))
		return -1;

	int ret = send_packet_tcp_connection(c->tcp_c, connections_number, data, sizeof(data));
	return ret;
}


/* Handle a cookie response packet of length encrypted with shared_key.
 * put the cookie in the response in cookie
 *
 * cookie must be of length COOKIE_LENGTH.
 *
 * return -1 on failure.
 * return COOKIE_LENGTH on success.
 */
static int handle_cookie_response(uint8_t* cookie, uint64_t* number, const uint8_t* packet, uint16_t length,	const uint8_t* shared_key)
{
	if (length != COOKIE_RESPONSE_LENGTH)
		return -1;

	uint8_t plain[COOKIE_LENGTH + sizeof(uint64_t)];
	int len =CryptoCore::decryptDataSymmetric(shared_key, packet + 1, packet + 1 + crypto_box_NONCEBYTES,length - (1 + crypto_box_NONCEBYTES), plain);

	if (len != sizeof(plain))
		return -1;

	memcpy(cookie, plain, COOKIE_LENGTH);
	memcpy(number, plain + COOKIE_LENGTH, sizeof(uint64_t));
	return COOKIE_LENGTH;
}


/* Create a handshake packet and put it in packet.
 * cookie must be COOKIE_LENGTH bytes.
 * packet must be of size HANDSHAKE_PACKET_LENGTH or bigger.
 *
 * return -1 on failure.
 * return HANDSHAKE_PACKET_LENGTH on success.
 */
static int create_crypto_handshake(const Net_Crypto* c, uint8_t* packet, const uint8_t* cookie, const uint8_t* nonce,
	const uint8_t* session_pk, const uint8_t* peer_real_pk, const uint8_t* peer_dht_pubkey)
{
	uint8_t plain[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES + COOKIE_LENGTH];
	memcpy(plain, nonce, crypto_box_NONCEBYTES);
	memcpy(plain + crypto_box_NONCEBYTES, session_pk, crypto_box_PUBLICKEYBYTES);
	crypto_hash_sha512(plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES, cookie, COOKIE_LENGTH);
	uint8_t cookie_plain[COOKIE_DATA_LENGTH];
	memcpy(cookie_plain, peer_real_pk, crypto_box_PUBLICKEYBYTES);
	memcpy(cookie_plain + crypto_box_PUBLICKEYBYTES, peer_dht_pubkey, crypto_box_PUBLICKEYBYTES);

	if (create_cookie(plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES, cookie_plain,
		c->secret_symmetric_key) != 0)
		return -1;

	 CryptoCore::newNonce(packet + 1 + COOKIE_LENGTH);
	int len =CryptoCore::encrypt_data(peer_real_pk, c->self_secret_key, packet + 1 + COOKIE_LENGTH, plain, sizeof(plain),
		packet + 1 + COOKIE_LENGTH + crypto_box_NONCEBYTES);

	if (len != HANDSHAKE_PACKET_LENGTH - (1 + COOKIE_LENGTH + crypto_box_NONCEBYTES))
		return -1;

	packet[0] = NET_PACKET_CRYPTO_HS;
	memcpy(packet + 1, cookie, COOKIE_LENGTH);

	return HANDSHAKE_PACKET_LENGTH;
}



/* Add a new temp packet to send repeatedly.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int new_temp_packet(const Net_Crypto* c, int crypt_connection_id, const uint8_t* packet, uint16_t length)
{
	if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE)
		return -1;

	Crypto_Connection * conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	uint8_t * temp_packet =(uint8_t * )malloc(length);

	if (temp_packet == 0)
		return -1;

	if (conn->temp_packet)
		free(conn->temp_packet);

	memcpy(temp_packet, packet, length);
	conn->temp_packet = temp_packet;
	conn->temp_packet_length = length;
	conn->temp_packet_sent_time = 0;
	conn->temp_packet_num_sent = 0;
	return 0;
}

/* Return the IP_Port that should be used to send packets to the other peer.
 *
 * return IP_Port with family 0 on failure.
 * return IP_Port on success.
 */
IP_Port return_ip_port_connection(Net_Crypto* c, int crypt_connection_id)
{
	IP_Port empty;
	empty.ip.family = 0;

	Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return empty;

	uint64_t current_time = unix_time();
	bool v6 = 0, v4 = 0;

	if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev4) > current_time) {
		v4 = 1;
	}

	if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev6) > current_time) {
		v6 = 1;
	}

	if (v4 && LAN_ip(conn->ip_portv4.ip) == 0) {
		return conn->ip_portv4;
	}
	else if (v6 && conn->ip_portv6.ip.family == AF_INET6) {
		return conn->ip_portv6;
	}
	else if (conn->ip_portv4.ip.family == AF_INET) {
		return conn->ip_portv4;
	}
	else {
		return empty;
	}
}



/* return one of CRYPTO_CONN_* values indicating the state of the connection.
 *
 * sets direct_connected to 1 if connection connects directly to other, 0 if it isn't.
 * sets online_tcp_relays to the number of connected tcp relays this connection has.
 */
unsigned int crypto_connection_status(const Net_Crypto* c, int crypt_connection_id, bool* direct_connected,
	unsigned int* online_tcp_relays)
{
	Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return CRYPTO_CONN_NO_CONNECTION;

	if (direct_connected) {
		*direct_connected = 0;

		uint64_t current_time = unix_time();

		if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev4) > current_time)
			* direct_connected = 1;

		if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev6) > current_time)
			* direct_connected = 1;
	}

	if (online_tcp_relays) {
		*online_tcp_relays = tcp_connection_to_online_tcp_relays(c->tcp_c, conn->connection_number_tcp);
	}

	return conn->status;
}


/* Sends a packet to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_packet_to(Net_Crypto* c, int crypt_connection_id, const uint8_t* data, uint16_t length)
{
	//TODO TCP, etc...
	Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	int direct_send_attempt = 0;

	//pthread_mutex_lock(&conn->mutex);
	IP_Port ip_port = return_ip_port_connection(c, crypt_connection_id);

	//TODO: on bad networks, direct connections might not last indefinitely.
	if (ip_port.ip.family != 0) {
		bool direct_connected = 0;
		crypto_connection_status(c, crypt_connection_id, &direct_connected, NULL);

		if (direct_connected) {
			if ((uint32_t)c->m_dht->getNetwork()->sendpacket(ip_port, data, length) == length) {
				//pthread_mutex_unlock(&conn->mutex);
				return 0;
			}
			else {
				//pthread_mutex_unlock(&conn->mutex);
				return -1;
			}
		}

		//TODO: a better way of sending packets directly to confirm the others ip.
		uint64_t current_time = unix_time();

		if ((((UDP_DIRECT_TIMEOUT / 2) + conn->direct_send_attempt_time) > current_time && length < 96)
			|| data[0] == NET_PACKET_COOKIE_REQUEST || data[0] == NET_PACKET_CRYPTO_HS) {
			if ((uint32_t)c->m_dht->getNetwork()->sendpacket( ip_port, data, length) == length)
			{
				direct_send_attempt = 1;
				conn->direct_send_attempt_time = unix_time();
			}
		}
	}

	//pthread_mutex_unlock(&conn->mutex);
	//pthread_mutex_lock(&c->tcp_mutex);
	int ret = send_packet_tcp_connection(c->tcp_c, conn->connection_number_tcp, data, length);
	//pthread_mutex_unlock(&c->tcp_mutex);

	//pthread_mutex_lock(&conn->mutex);

	if (ret == 0) {
		conn->last_tcp_sent = current_time_monotonic();
	}

	//pthread_mutex_unlock(&conn->mutex);

	if (ret == 0 || direct_send_attempt) {
		return 0;
	}

	return -1;
}


/* Send the temp packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_temp_packet(Net_Crypto* c, int crypt_connection_id)
{
	Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	if (!conn->temp_packet)
		return -1;

	if (send_packet_to(c, crypt_connection_id, conn->temp_packet, conn->temp_packet_length) != 0)
		return -1;

	conn->temp_packet_sent_time = current_time_monotonic();
	++conn->temp_packet_num_sent;
	return 0;
}


/* Create a handshake packet and set it as a temp packet.
 * cookie must be COOKIE_LENGTH.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int create_send_handshake(Net_Crypto* c, int crypt_connection_id, const uint8_t* cookie,	const uint8_t* dht_public_key)
{
	Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	uint8_t handshake_packet[HANDSHAKE_PACKET_LENGTH];

	if (create_crypto_handshake(c, handshake_packet, cookie, conn->sent_nonce, conn->sessionpublic_key,
		conn->public_key, dht_public_key) != sizeof(handshake_packet))
		return -1;

	if (new_temp_packet(c, crypt_connection_id, handshake_packet, sizeof(handshake_packet)) != 0)
		return -1;

	send_temp_packet(c, crypt_connection_id);
	return 0;
}

/* Open cookie of length COOKIE_LENGTH to bytes of length COOKIE_DATA_LENGTH using encryption_key
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int open_cookie(uint8_t* bytes, const uint8_t* cookie, const uint8_t* encryption_key)
{
	uint8_t contents[COOKIE_CONTENTS_LENGTH];
	int len = CryptoCore::decryptDataSymmetric(encryption_key, cookie, cookie + crypto_box_NONCEBYTES,
		COOKIE_LENGTH - crypto_box_NONCEBYTES, contents);

	if (len != sizeof(contents))
		return -1;

	uint64_t cookie_time;
	memcpy(&cookie_time, contents, sizeof(cookie_time));
	uint64_t temp_time = unix_time();

	if (cookie_time + COOKIE_TIMEOUT < temp_time || temp_time < cookie_time)
		return -1;

	memcpy(bytes, contents + sizeof(cookie_time), COOKIE_DATA_LENGTH);
	return 0;
}



/* Handle a crypto handshake packet of length.
 * put the nonce contained in the packet in nonce,
 * the session public key in session_pk
 * the real public key of the peer in peer_real_pk
 * the dht public key of the peer in dht_public_key and
 * the cookie inside the encrypted part of the packet in cookie.
 *
 * if expected_real_pk isn't NULL it denotes the real public key
 * the packet should be from.
 *
 * nonce must be at least crypto_box_NONCEBYTES
 * session_pk must be at least crypto_box_PUBLICKEYBYTES
 * peer_real_pk must be at least crypto_box_PUBLICKEYBYTES
 * cookie must be at least COOKIE_LENGTH
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_crypto_handshake(const Net_Crypto* c, uint8_t* nonce, uint8_t* session_pk, uint8_t* peer_real_pk,
	uint8_t* dht_public_key, uint8_t* cookie, const uint8_t* packet, uint16_t length, const uint8_t* expected_real_pk)
{
	if (length != HANDSHAKE_PACKET_LENGTH)
		return -1;

	uint8_t cookie_plain[COOKIE_DATA_LENGTH];

	if (open_cookie(cookie_plain, packet + 1, c->secret_symmetric_key) != 0)
		return -1;

	if (expected_real_pk)
		if ( CryptoCore::publicKeyCmp(cookie_plain, expected_real_pk) != 0)
			return -1;

	uint8_t cookie_hash[crypto_hash_sha512_BYTES];
	crypto_hash_sha512(cookie_hash, packet + 1, COOKIE_LENGTH);

	uint8_t plain[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES + COOKIE_LENGTH];
	int len =CryptoCore::decrypt_data(cookie_plain, c->self_secret_key, packet + 1 + COOKIE_LENGTH,
		packet + 1 + COOKIE_LENGTH + crypto_box_NONCEBYTES,	HANDSHAKE_PACKET_LENGTH - (1 + COOKIE_LENGTH + crypto_box_NONCEBYTES), plain);

	if (len != sizeof(plain))
		return -1;

	if (sodium_memcmp(cookie_hash, plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
		crypto_hash_sha512_BYTES) != 0)
		return -1;

	memcpy(nonce, plain, crypto_box_NONCEBYTES);
	memcpy(session_pk, plain + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);
	memcpy(cookie, plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES, COOKIE_LENGTH);
	memcpy(peer_real_pk, cookie_plain, crypto_box_PUBLICKEYBYTES);
	memcpy(dht_public_key, cookie_plain + crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	return 0;
}


/* Get the lowest 2 bytes from the nonce and convert
 * them to host byte format before returning them.
 */
static uint16_t get_nonce_uint16(const uint8_t* nonce)
{
	uint16_t num;
	memcpy(&num, nonce + (crypto_box_NONCEBYTES - sizeof(uint16_t)), sizeof(uint16_t));
	return ntohs(num);
}

/* Handle a data packet.
 * Decrypt packet of length and put it into data.
 * data must be at least MAX_DATA_DATA_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of data on success.
 */
static int handle_data_packet(const Net_Crypto* c, int crypt_connection_id, uint8_t* data, const uint8_t* packet,	uint16_t length)
{
	if (length <= (1 + sizeof(uint16_t) + crypto_box_MACBYTES) || length > MAX_CRYPTO_PACKET_SIZE)
		return -1;

	Crypto_Connection * conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	uint8_t nonce[crypto_box_NONCEBYTES];
	memcpy(nonce, conn->recv_nonce, crypto_box_NONCEBYTES);
	uint16_t num_cur_nonce = get_nonce_uint16(nonce);
	uint16_t num;
	memcpy(&num, packet + 1, sizeof(uint16_t));
	num = ntohs(num);
	uint16_t diff = num - num_cur_nonce;
	increment_nonce_number(nonce, diff);
	int len =CryptoCore::decryptDataSymmetric(conn->shared_key, nonce, packet + 1 + sizeof(uint16_t),
		length - (1 + sizeof(uint16_t)), data);

	if ((unsigned int)len != length - (1 + sizeof(uint16_t) + crypto_box_MACBYTES))
		return -1;

	if (diff > DATA_NUM_THRESHOLD * 2) {
		increment_nonce_number(conn->recv_nonce, DATA_NUM_THRESHOLD);
	}

	return len;
}


/* Get pointer of data with packet number.
 *
 * return -1 on failure.
 * return 0 if data at number is empty.
 * return 1 if data pointer was put in data.
 */
static int get_data_pointer(const Packets_Array* array, Packet_Data** data, uint32_t number)
{
	uint32_t num_spots = array->buffer_end - array->buffer_start;

	if (array->buffer_end - number > num_spots || number - array->buffer_start >= num_spots)
		return -1;

	uint32_t num = number % CRYPTO_PACKET_BUFFER_SIZE;

	if (!array->buffer[num])
		return 0;

	*data = array->buffer[num];
	return 1;
}


/* Delete all packets in array before number (but not number)
 *
 * return -1 on failure.
 * return 0 on success
 */
static int clear_buffer_until(Packets_Array* array, uint32_t number)
{
	uint32_t num_spots = array->buffer_end - array->buffer_start;

	if (array->buffer_end - number >= num_spots || number - array->buffer_start > num_spots)
		return -1;

	uint32_t i;

	for (i = array->buffer_start; i != number; ++i) {
		uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

		if (array->buffer[num]) {
			free(array->buffer[num]);
			array->buffer[num] = NULL;
		}
	}

	array->buffer_start = i;
	return 0;
}



/* Creates and sends a data packet to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_data_packet(Net_Crypto * c, int crypt_connection_id, const uint8_t * data, uint16_t length)
{
	if (length == 0 || length + (1 + sizeof(uint16_t) + crypto_box_MACBYTES) > MAX_CRYPTO_PACKET_SIZE)
		return -1;

	Crypto_Connection * conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	//pthread_mutex_lock(&conn->mutex);
	uint8_t *packet = new uint8_t[1 + sizeof(uint16_t) + length + crypto_box_MACBYTES];
	packet[0] = NET_PACKET_CRYPTO_DATA;
	memcpy(packet + 1, conn->sent_nonce + (crypto_box_NONCEBYTES - sizeof(uint16_t)), sizeof(uint16_t));
	int len =CryptoCore::encryptDataSymmetric(conn->shared_key, conn->sent_nonce, data, length, packet + 1 + sizeof(uint16_t));

	if (len + 1 + sizeof(uint16_t) != sizeof(packet)) {
		//pthread_mutex_unlock(&conn->mutex);
		return -1;
	}

	increment_nonce(conn->sent_nonce);
	//pthread_mutex_unlock(&conn->mutex);

	return send_packet_to(c, crypt_connection_id, packet, sizeof(packet));
}

/* Creates and sends a data packet with buffer_start and num to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_data_packet_helper(Net_Crypto* c, int crypt_connection_id, uint32_t buffer_start, uint32_t num,
	const uint8_t* data, uint16_t length)
{
	if (length == 0 || length > MAX_CRYPTO_DATA_SIZE)
		return -1;

	num = htonl(num);
	buffer_start = htonl(buffer_start);
	uint16_t padding_length = (MAX_CRYPTO_DATA_SIZE - length) % CRYPTO_MAX_PADDING;
	uint8_t *packet = new uint8_t[sizeof(uint32_t) + sizeof(uint32_t) + padding_length + length];
	memcpy(packet, &buffer_start, sizeof(uint32_t));
	memcpy(packet + sizeof(uint32_t), &num, sizeof(uint32_t));
	memset(packet + (sizeof(uint32_t) * 2), PACKET_ID_PADDING, padding_length);
	memcpy(packet + (sizeof(uint32_t) * 2) + padding_length, data, length);

	return send_data_packet(c, crypt_connection_id, packet, sizeof(packet));
}

/* Send a kill packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_kill_packet(Net_Crypto* c, int crypt_connection_id)
{
	Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	uint8_t kill_packet = PACKET_ID_KILL;
	return send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, conn->send_array.buffer_end,
		&kill_packet, sizeof(kill_packet));
}

static int clear_buffer(Packets_Array* array)
{
	uint32_t i;

	for (i = array->buffer_start; i != array->buffer_end; ++i) {
		uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

		if (array->buffer[num]) {
			free(array->buffer[num]);
			array->buffer[num] = NULL;
		}
	}

	array->buffer_start = i;
	return 0;
}



/* Clear the temp packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int clear_temp_packet(const Net_Crypto* c, int crypt_connection_id)
{
	Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	if (conn->temp_packet)
		free(conn->temp_packet);

	conn->temp_packet = 0;
	conn->temp_packet_length = 0;
	conn->temp_packet_sent_time = 0;
	conn->temp_packet_num_sent = 0;
	return 0;
}

/* Set the size of the friend list to numfriends.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
static int realloc_cryptoconnection(Net_Crypto* c, uint32_t num)
{
	if (num == 0) {
		free(c->crypto_connections);
		c->crypto_connections = NULL;
		return 0;
	}

	Crypto_Connection* newcrypto_connections = (Crypto_Connection*)realloc(c->crypto_connections, num * sizeof(Crypto_Connection));

	if (newcrypto_connections == NULL)
		return -1;

	c->crypto_connections = newcrypto_connections;
	return 0;
}



/* Wipe a crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_crypto_connection(Net_Crypto* c, int crypt_connection_id)
{
	if (crypt_connection_id_not_valid(c, crypt_connection_id))
		return -1;

	uint32_t i;

	/* Keep mutex, only destroy it when connection is realloced out. */
	pthread_mutex_t mutex = c->crypto_connections[crypt_connection_id].mutex;
	sodium_memzero(&(c->crypto_connections[crypt_connection_id]), sizeof(Crypto_Connection));
	c->crypto_connections[crypt_connection_id].mutex = mutex;

	for (i = c->crypto_connections_length; i != 0; --i) {
		if (c->crypto_connections[i - 1].status == CRYPTO_CONN_NO_CONNECTION) {
			//pthread_mutex_destroy(&c->crypto_connections[i - 1].mutex);
		}
		else {
			break;
		}
	}

	if (c->crypto_connections_length != i) {
		c->crypto_connections_length = i;
		realloc_cryptoconnection(c, c->crypto_connections_length);
	}

	return 0;
}




/* Kill a crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int crypto_kill(Net_Crypto* c, int crypt_connection_id)
{
	while (1) { /* TODO: is this really the best way to do this? */
		//pthread_mutex_lock(&c->connections_mutex);

		if (!c->connection_use_counter) {
			break;
		}

		//pthread_mutex_unlock(&c->connections_mutex);
	}

	Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

	int ret = -1;

	if (conn) {
		if (conn->status == CRYPTO_CONN_ESTABLISHED)
			send_kill_packet(c, crypt_connection_id);

		//pthread_mutex_lock(&c->tcp_mutex);
		kill_tcp_connection_to(c->tcp_c, conn->connection_number_tcp);
		//pthread_mutex_unlock(&c->tcp_mutex);

		bs_list_remove(&c->ip_port_list, (uint8_t*)& conn->ip_portv4, crypt_connection_id);
		bs_list_remove(&c->ip_port_list, (uint8_t*)& conn->ip_portv6, crypt_connection_id);
		clear_temp_packet(c, crypt_connection_id);
		clear_buffer(&conn->send_array);
		clear_buffer(&conn->recv_array);
		ret = wipe_crypto_connection(c, crypt_connection_id);
	}

	//pthread_mutex_unlock(&c->connections_mutex);

	return ret;
}


static void connection_kill(Net_Crypto* c, int crypt_connection_id)
{
	Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return;

	if (conn->connection_status_callback) {
		conn->connection_status_callback(conn->connection_status_callback_object, conn->connection_status_callback_id, 0);
	}

	crypto_kill(c, crypt_connection_id);
}




/* Handle a request data packet.
 * Remove all the packets the other received from the array.
 *
 * return -1 on failure.
 * return number of requested packets on success.
 */
static int handle_request_packet(Packets_Array* send_array, const uint8_t* data, uint16_t length,	uint64_t* latest_send_time, uint64_t rtt_time)
{
	if (length < 1)
		return -1;

	if (data[0] != PACKET_ID_REQUEST)
		return -1;

	if (length == 1)
		return 0;

	++data;
	--length;

	uint32_t i, n = 1;
	uint32_t requested = 0;

	uint64_t temp_time = current_time_monotonic();
	uint64_t l_sent_time = ~0;

	for (i = send_array->buffer_start; i != send_array->buffer_end; ++i) {
		if (length == 0)
			break;

		uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

		if (n == data[0]) {
			if (send_array->buffer[num]) {
				uint64_t sent_time = send_array->buffer[num]->sent_time;

				if ((sent_time + rtt_time) < temp_time) {
					send_array->buffer[num]->sent_time = 0;
				}
			}

			++data;
			--length;
			n = 0;
			++requested;
		}
		else {
			if (send_array->buffer[num]) {
				uint64_t sent_time = send_array->buffer[num]->sent_time;

				if (l_sent_time < sent_time)
					l_sent_time = sent_time;

				free(send_array->buffer[num]);
				send_array->buffer[num] = NULL;
			}
		}

		if (n == 255) {
			n = 1;

			if (data[0] != 0)
				return -1;

			++data;
			--length;
		}
		else {
			++n;
		}
	}

	if (*latest_send_time < l_sent_time)
		* latest_send_time = l_sent_time;

	return requested;
}

/* Set array buffer end to number.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int set_buffer_end(Packets_Array* array, uint32_t number)
{
	if ((number - array->buffer_start) > CRYPTO_PACKET_BUFFER_SIZE)
		return -1;

	if ((number - array->buffer_end) > CRYPTO_PACKET_BUFFER_SIZE)
		return -1;

	array->buffer_end = number;
	return 0;
}

/* Add data with packet number to array.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int add_data_to_buffer(Packets_Array* array, uint32_t number, const Packet_Data* data)
{
	if (number - array->buffer_start > CRYPTO_PACKET_BUFFER_SIZE)
		return -1;

	uint32_t num = number % CRYPTO_PACKET_BUFFER_SIZE;

	if (array->buffer[num])
		return -1;

	Packet_Data * new_d = (Packet_Data*)malloc(sizeof(Packet_Data));

	if (new_d == NULL)
		return -1;

	memcpy(new_d, data, sizeof(Packet_Data));
	array->buffer[num] = new_d;

	if ((number - array->buffer_start) >= (array->buffer_end - array->buffer_start))
		array->buffer_end = number + 1;

	return 0;
}



/* Read data from begginning of array.
 *
 * return -1 on failure.
 * return packet number on success.
 */
static int64_t read_data_beg_buffer(Packets_Array* array, Packet_Data* data)
{
	if (array->buffer_end == array->buffer_start)
		return -1;

	uint32_t num = array->buffer_start % CRYPTO_PACKET_BUFFER_SIZE;

	if (!array->buffer[num])
		return -1;

	memcpy(data, array->buffer[num], sizeof(Packet_Data));
	uint32_t id = array->buffer_start;
	++array->buffer_start;
	free(array->buffer[num]);
	array->buffer[num] = NULL;
	return id;
}

/* Handle a received data packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_data_packet_helper(Net_Crypto* c, int crypt_connection_id, const uint8_t* packet, uint16_t length,
	bool udp)
{
	if (length > MAX_CRYPTO_PACKET_SIZE || length <= CRYPTO_DATA_PACKET_MIN_SIZE)
		return -1;

	Crypto_Connection * conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	uint8_t data[MAX_DATA_DATA_PACKET_SIZE];
	int len = handle_data_packet(c, crypt_connection_id, data, packet, length);

	if (len <= (int)(sizeof(uint32_t) * 2))
		return -1;

	uint32_t buffer_start, num;
	memcpy(&buffer_start, data, sizeof(uint32_t));
	memcpy(&num, data + sizeof(uint32_t), sizeof(uint32_t));
	buffer_start = ntohl(buffer_start);
	num = ntohl(num);

	uint64_t rtt_calc_time = 0;

	if (buffer_start != conn->send_array.buffer_start) {
		Packet_Data* packet_time;

		if (get_data_pointer(&conn->send_array, &packet_time, conn->send_array.buffer_start) == 1) {
			rtt_calc_time = packet_time->sent_time;
		}

		if (clear_buffer_until(&conn->send_array, buffer_start) != 0) {
			return -1;
		}
	}

	uint8_t* real_data = data + (sizeof(uint32_t) * 2);
	uint16_t real_length = len - (sizeof(uint32_t) * 2);

	while (real_data[0] == PACKET_ID_PADDING) { /* Remove Padding */
		++real_data;
		--real_length;

		if (real_length == 0)
			return -1;
	}

	if (real_data[0] == PACKET_ID_KILL) {
		connection_kill(c, crypt_connection_id);
		return 0;
	}

	if (conn->status == CRYPTO_CONN_NOT_CONFIRMED) {
		clear_temp_packet(c, crypt_connection_id);
		conn->status = CRYPTO_CONN_ESTABLISHED;

		if (conn->connection_status_callback)
			conn->connection_status_callback(conn->connection_status_callback_object, conn->connection_status_callback_id, 1);
	}

	if (real_data[0] == PACKET_ID_REQUEST) {
		uint64_t rtt_time;

		if (udp) {
			rtt_time = conn->rtt_time;
		}
		else {
			rtt_time = DEFAULT_TCP_PING_CONNECTION;
		}

		int requested = handle_request_packet(&conn->send_array, real_data, real_length, &rtt_calc_time, rtt_time);

		if (requested == -1) {
			return -1;
		}
		else {
			//TODO?
		}

		set_buffer_end(&conn->recv_array, num);
	}
	else if (real_data[0] >= CRYPTO_RESERVED_PACKETS && real_data[0] < PACKET_ID_LOSSY_RANGE_START) {
		Packet_Data dt;
		dt.length = real_length;
		memcpy(dt.data, real_data, real_length);

		if (add_data_to_buffer(&conn->recv_array, num, &dt) != 0)
			return -1;


		while (1) {
			//pthread_mutex_lock(&conn->mutex);
			int ret = read_data_beg_buffer(&conn->recv_array, &dt);
			//pthread_mutex_unlock(&conn->mutex);

			if (ret == -1)
				break;

			if (conn->connection_data_callback)
				conn->connection_data_callback(conn->connection_data_callback_object, conn->connection_data_callback_id, dt.data,
					dt.length);

			/* conn might get killed in callback. */
			conn = get_crypto_connection(c, crypt_connection_id);

			if (conn == 0)
				return -1;
		}

		/* Packet counter. */
		++conn->packet_counter;
	}
	else if (real_data[0] >= PACKET_ID_LOSSY_RANGE_START &&
		real_data[0] < (PACKET_ID_LOSSY_RANGE_START + PACKET_ID_LOSSY_RANGE_SIZE)) {

		set_buffer_end(&conn->recv_array, num);

		if (conn->connection_lossy_data_callback)
			conn->connection_lossy_data_callback(conn->connection_lossy_data_callback_object,
				conn->connection_lossy_data_callback_id, real_data, real_length);

	}
	else {
		return -1;
	}

	if (rtt_calc_time != 0) {
		uint64_t rtt_time = current_time_monotonic() - rtt_calc_time;

		if (rtt_time < conn->rtt_time)
			conn->rtt_time = rtt_time;
	}

	return 0;
}


/* Handle a packet that was received for the connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_packet_connection(Net_Crypto* c, int crypt_connection_id, const uint8_t* packet, uint16_t length,	bool udp)
{
	if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE)
		return -1;

	Crypto_Connection * conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	switch (packet[0]) {
	case NET_PACKET_COOKIE_RESPONSE: {
		if (conn->status != CRYPTO_CONN_COOKIE_REQUESTING)
			return -1;

		uint8_t cookie[COOKIE_LENGTH];
		uint64_t number;

		if (handle_cookie_response(cookie, &number, packet, length, conn->shared_key) != sizeof(cookie))
			return -1;

		if (number != conn->cookie_request_number)
			return -1;

		if (create_send_handshake(c, crypt_connection_id, cookie, conn->dht_public_key) != 0)
			return -1;

		conn->status = CRYPTO_CONN_HANDSHAKE_SENT;
		return 0;
	}

	case NET_PACKET_CRYPTO_HS: {
		if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING || conn->status == CRYPTO_CONN_HANDSHAKE_SENT
			|| conn->status == CRYPTO_CONN_NOT_CONFIRMED) {
			uint8_t peer_real_pk[crypto_box_PUBLICKEYBYTES];
			uint8_t dht_public_key[crypto_box_PUBLICKEYBYTES];
			uint8_t cookie[COOKIE_LENGTH];

			if (handle_crypto_handshake(c, conn->recv_nonce, conn->peersessionpublic_key, peer_real_pk, dht_public_key, cookie,
				packet, length, conn->public_key) != 0)
				return -1;

			if (CryptoCore::publicKeyCmp(dht_public_key, conn->dht_public_key) == 0) {
				CryptoCore::encryptPrecompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);

				if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) {
					if (create_send_handshake(c, crypt_connection_id, cookie, dht_public_key) != 0)
						return -1;
				}

				conn->status = CRYPTO_CONN_NOT_CONFIRMED;
			}
			else {
				if (conn->dht_pk_callback)
					conn->dht_pk_callback(conn->dht_pk_callback_object, conn->dht_pk_callback_number, dht_public_key);
			}

		}
		else {
			return -1;
		}

		return 0;
	}

	case NET_PACKET_CRYPTO_DATA: {
		if (conn->status == CRYPTO_CONN_NOT_CONFIRMED || conn->status == CRYPTO_CONN_ESTABLISHED) {
			return handle_data_packet_helper(c, crypt_connection_id, packet, length, udp);
		}
		else {
			return -1;
		}

		return 0;
	}

	default: {
		return -1;
	}
	}

	return 0;
}

/* Handle the cookie request packet (for TCP oob packets)
 */
static int tcp_oob_handle_cookie_request(const Net_Crypto* c, unsigned int tcp_connections_number,
	const uint8_t* dht_public_key, const uint8_t* packet, uint16_t length)
{
	uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
	uint8_t shared_key[crypto_box_BEFORENMBYTES];
	uint8_t dht_public_key_temp[crypto_box_PUBLICKEYBYTES];

	if (handle_cookie_request(c, request_plain, shared_key, dht_public_key_temp, packet, length) != 0)
		return -1;

	if (CryptoCore::publicKeyCmp(dht_public_key, dht_public_key_temp) != 0)
		return -1;

	uint8_t data[COOKIE_RESPONSE_LENGTH];

	if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data))
		return -1;

	int ret = tcp_send_oob_packet(c->tcp_c, tcp_connections_number, dht_public_key, data, sizeof(data));
	return ret;
}


/* Get crypto connection id from public key of peer.
 *
 *  return -1 if there are no connections like we are looking for.
 *  return id if it found it.
 */
static int getcryptconnection_id(const Net_Crypto* c, const uint8_t* public_key)
{
	uint32_t i;

	for (i = 0; i < c->crypto_connections_length; ++i) {
		if (c->crypto_connections[i].status != CRYPTO_CONN_NO_CONNECTION)
			if (CryptoCore::publicKeyCmp(public_key, c->crypto_connections[i].public_key) == 0)
				return i;
	}

	return -1;
}

/* Associate an ip_port to a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int add_ip_port_connection(Net_Crypto* c, int crypt_connection_id, IP_Port ip_port)
{
	Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	if (ip_port.ip.family == AF_INET) {
		if (!ipport_equal(&ip_port, &conn->ip_portv4) && LAN_ip(conn->ip_portv4.ip) != 0) {
			if (!bs_list_add(&c->ip_port_list, (uint8_t*)& ip_port, crypt_connection_id))
				return -1;

			bs_list_remove(&c->ip_port_list, (uint8_t*)& conn->ip_portv4, crypt_connection_id);
			conn->ip_portv4 = ip_port;
			return 0;
		}
	}
	else if (ip_port.ip.family == AF_INET6) {
		if (!ipport_equal(&ip_port, &conn->ip_portv6)) {
			if (!bs_list_add(&c->ip_port_list, (uint8_t*)& ip_port, crypt_connection_id))
				return -1;

			bs_list_remove(&c->ip_port_list, (uint8_t*)& conn->ip_portv6, crypt_connection_id);
			conn->ip_portv6 = ip_port;
			return 0;
		}
	}

	return -1;
}


static TCP_Connection_to* get_connection(const TCP_Connections* tcp_c, int connections_number)
{
	if (connections_number_not_valid(tcp_c, connections_number))
		return 0;

	return &tcp_c->connections[connections_number];
}


static bool tcp_connection_in_conn(TCP_Connection_to* con_to, unsigned int tcp_connections_number)
{
	unsigned int i;

	for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
		if (con_to->connections[i].tcp_connection == (tcp_connections_number + 1)) {
			return 1;
		}
	}

	return 0;
}


/* return index on success.
 * return -1 on failure.
 */
static int add_tcp_connection_to_conn(TCP_Connection_to* con_to, unsigned int tcp_connections_number)
{
	unsigned int i;

	if (tcp_connection_in_conn(con_to, tcp_connections_number))
		return -1;

	for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
		if (con_to->connections[i].tcp_connection == 0) {
			con_to->connections[i].tcp_connection = tcp_connections_number + 1;
			con_to->connections[i].status = TCP_CONNECTIONS_STATUS_NONE;
			con_to->connections[i].connection_id = 0;
			return i;
		}
	}

	return -1;
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
	new1 = (TCP_Priority_List*)malloc(sizeof(TCP_Priority_List) + size);

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

	uint8_t *packet=new uint8_t[sizeof(uint16_t) + length + crypto_box_MACBYTES];

	uint16_t c_length = htons(length + crypto_box_MACBYTES);
	memcpy(packet, &c_length, sizeof(uint16_t));
	int len = CryptoCore::encryptDataSymmetric(con->shared_key, con->sent_nonce, data, length, packet + sizeof(uint16_t));

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
int send_routing_request(TCP_Client_Connection* con, uint8_t* public_key)
{
	uint8_t packet[1 + crypto_box_PUBLICKEYBYTES];
	packet[0] = TCP_PACKET_ROUTING_REQUEST;
	memcpy(packet + 1, public_key, crypto_box_PUBLICKEYBYTES);
	return write_packet_TCP_secure_connection(con, packet, sizeof(packet), 1);
}

/* Send a TCP routing request.
 *
 * return 0 on success.
 * return -1 on failure.
 */
static int send_tcp_relay_routing_request(TCP_Connections* tcp_c, int tcp_connections_number, uint8_t* public_key)
{
	TCP_con* tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

	if (!tcp_con)
		return -1;

	if (tcp_con->status == TCP_CONN_SLEEPING)
		return -1;

	if (send_routing_request(tcp_con->connection, public_key) != 1)
		return -1;

	return 0;
}

/* Add a TCP relay tied to a connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_number_relay_connection(TCP_Connections* tcp_c, int connections_number, unsigned int tcp_connections_number)
{
	TCP_Connection_to* con_to = get_connection(tcp_c, connections_number);

	if (!con_to)
		return -1;

	TCP_con* tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

	if (!tcp_con)
		return -1;

	if (con_to->status != TCP_CONN_SLEEPING && tcp_con->status == TCP_CONN_SLEEPING) {
		tcp_con->unsleep = 1;
	}

	if (add_tcp_connection_to_conn(con_to, tcp_connections_number) == -1)
		return -1;

	if (tcp_con->status == TCP_CONN_CONNECTED) {
		if (send_tcp_relay_routing_request(tcp_c, tcp_connections_number, con_to->public_key) == 0) {
			tcp_con->connected_time = unix_time();
		}
	}

	return 0;
}


/* Add a source to the crypto connection.
 * This is to be used only when we have received a packet from that source.
 *
 *  return -1 on failure.
 *  return positive number on success.
 *  0 if source was a direct UDP connection.
 */
static int crypto_connection_add_source(Net_Crypto* c, int crypt_connection_id, IP_Port source)
{
	Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	if (source.ip.family == AF_INET || source.ip.family == AF_INET6) {
		if (add_ip_port_connection(c, crypt_connection_id, source) != 0)
			return -1;

		if (source.ip.family == AF_INET) {
			conn->direct_lastrecv_timev4 = unix_time();
		}
		else {
			conn->direct_lastrecv_timev6 = unix_time();
		}

		return 0;
	}
	else if (source.ip.family == TCP_FAMILY) {
		if (add_tcp_number_relay_connection(c->tcp_c, conn->connection_number_tcp, source.ip.ip6.uint32[0]) == 0)
			return 1;
	}

	return -1;
}


/* Handle a handshake packet by someone who wants to initiate a new connection with us.
 * This calls the callback set by new_connection_handler() if the handshake is ok.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_new_connection_handshake(Net_Crypto* c, IP_Port source, const uint8_t* data, uint16_t length)
{
	New_Connection n_c;
	n_c.cookie = (uint8_t*)malloc(COOKIE_LENGTH);

	if (n_c.cookie == NULL)
		return -1;

	n_c.source = source;
	n_c.cookie_length = COOKIE_LENGTH;

	if (handle_crypto_handshake(c, n_c.recv_nonce, n_c.peersessionpublic_key, n_c.public_key, n_c.dht_public_key,
		n_c.cookie, data, length, 0) != 0) {
		free(n_c.cookie);
		return -1;
	}

	int crypt_connection_id = getcryptconnection_id(c, n_c.public_key);

	if (crypt_connection_id != -1) {
		Crypto_Connection* conn = get_crypto_connection(c, crypt_connection_id);

		if (CryptoCore::publicKeyCmp (n_c.dht_public_key, conn->dht_public_key) != 0) {
			connection_kill(c, crypt_connection_id);
		}
		else {
			int ret = -1;

			if (conn && (conn->status == CRYPTO_CONN_COOKIE_REQUESTING || conn->status == CRYPTO_CONN_HANDSHAKE_SENT)) {
				memcpy(conn->recv_nonce, n_c.recv_nonce, crypto_box_NONCEBYTES);
				memcpy(conn->peersessionpublic_key, n_c.peersessionpublic_key, crypto_box_PUBLICKEYBYTES);
				CryptoCore::encryptPrecompute (conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);

				 crypto_connection_add_source(c, crypt_connection_id, source);

				if (create_send_handshake(c, crypt_connection_id, n_c.cookie, n_c.dht_public_key) == 0) {
					conn->status = CRYPTO_CONN_NOT_CONFIRMED;
					ret = 0;
				}
			}

			free(n_c.cookie);
			return ret;
		}
	}

	int ret = c->new_connection_callback(c->new_connection_callback_object, &n_c);
	free(n_c.cookie);
	return ret;
}


static int tcp_data_callback(void* object, int id, const uint8_t* data, uint16_t length)
{
	if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE)
		return -1;

	Net_Crypto * c = (Net_Crypto*)object;

	Crypto_Connection * conn = get_crypto_connection(c, id);

	if (conn == 0)
		return -1;

	if (data[0] == NET_PACKET_COOKIE_REQUEST) {
		return tcp_handle_cookie_request(c, conn->connection_number_tcp, data, length);
	}

	//pthread_mutex_unlock(&c->tcp_mutex);
	int ret = handle_packet_connection(c, id, data, length, 0);
	//pthread_mutex_lock(&c->tcp_mutex);

	if (ret != 0)
		return -1;

	//TODO detect and kill bad TCP connections.
	return 0;
}

static int tcp_oob_callback(void* object, const uint8_t* public_key, unsigned int tcp_connections_number,
	const uint8_t* data, uint16_t length)
{
	if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE)
		return -1;

	Net_Crypto * c = (Net_Crypto * )object;

	if (data[0] == NET_PACKET_COOKIE_REQUEST) {
		return tcp_oob_handle_cookie_request(c, tcp_connections_number, public_key, data, length);
	}
	else if (data[0] == NET_PACKET_CRYPTO_HS) {
		IP_Port source;
		source.port = 0;
		source.ip.family = TCP_FAMILY;
		source.ip.ip6.uint32[0] = tcp_connections_number;

		if (handle_new_connection_handshake(c, source, data, length) != 0)
			return -1;

		return 0;
	}
	else {
		return -1;
	}
}


/* Handle the cookie request packet (for raw UDP)
 */
static int udp_handle_cookie_request(void* object, IP_Port source, const uint8_t* packet, uint16_t length)
{
	Net_Crypto* c =(Net_Crypto*) object;
	uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
	uint8_t shared_key[crypto_box_BEFORENMBYTES];
	uint8_t dht_public_key[crypto_box_PUBLICKEYBYTES];

	if (handle_cookie_request(c, request_plain, shared_key, dht_public_key, packet, length) != 0)
		return 1;

	uint8_t data[COOKIE_RESPONSE_LENGTH];

	if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data))
		return 1;

	if ((uint32_t) c->m_dht->getNetwork()->sendpacket( source, data, sizeof(data)) != sizeof(data))
		return 1;

	return 0;
}



/* Get the crypto connection id from the ip_port.
 *
 * return -1 on failure.
 * return connection id on success.
 */
static int crypto_id_ip_port(const Net_Crypto* c, IP_Port ip_port)
{
	return bs_list_find(&c->ip_port_list, (uint8_t*)& ip_port);
}

/* Handle raw UDP packets coming directly from the socket.
 *
 * Handles:
 * Cookie response packets.
 * Crypto handshake packets.
 * Crypto data packets.
 *
 */
static int udp_handle_packet(void* object, IP_Port source, const uint8_t* packet, uint16_t length)
{
	if (length <= CRYPTO_MIN_PACKET_SIZE || length > MAX_CRYPTO_PACKET_SIZE)
		return 1;

	Net_Crypto * c =(Net_Crypto *) object;
	int crypt_connection_id = crypto_id_ip_port(c, source);

	if (crypt_connection_id == -1) {
		if (packet[0] != NET_PACKET_CRYPTO_HS)
			return 1;

		if (handle_new_connection_handshake(c, source, packet, length) != 0)
			return 1;

		return 0;
	}

	if (handle_packet_connection(c, crypt_connection_id, packet, length, 1) != 0)
		return 1;

	Crypto_Connection * conn = get_crypto_connection(c, crypt_connection_id);

	if (conn == 0)
		return -1;

	pthread_mutex_lock(&conn->mutex);

	if (source.ip.family == AF_INET) {
		conn->direct_lastrecv_timev4 = unix_time();
	}
	else {
		conn->direct_lastrecv_timev6 = unix_time();
	}

	pthread_mutex_unlock(&conn->mutex);
	return 0;
}

Net_Crypto::Net_Crypto(QObject *parent)	: QObject(parent)
{
}

Net_Crypto::~Net_Crypto()
{
}

void Net_Crypto::new_keys()
{
	crypto_box_keypair(self_public_key, self_secret_key);
}

int Net_Crypto::init(std::shared_ptr<DHT> dht, TCP_Proxy_Info* proxy_info)
{
	unix_time_update();
	m_dht = dht;
	tcp_c = new TCP_Connections;
	if (tcp_c->init(m_dht->selfSecretKey(), proxy_info))
		return 1;

	tcp_c->set_packet_tcp_connection_callback(&tcp_data_callback, this);
	tcp_c->set_oob_packet_tcp_connection_callback(&tcp_oob_callback, this);


	if (create_recursive_mutex(&tcp_mutex) != 0 ||pthread_mutex_init(&connections_mutex, NULL) != 0)
	{
		kill_tcp_connections(tcp_c);		
		return 1;
	}	

	new_keys();
	 CryptoCore::new_symmetric_key(secret_symmetric_key);

	current_sleep_time = CRYPTO_SEND_PACKET_INTERVAL;

	m_dht->getNetwork()->networkingRegisterhandler( NET_PACKET_COOKIE_REQUEST, &udp_handle_cookie_request, this);
	m_dht->getNetwork()->networkingRegisterhandler( NET_PACKET_COOKIE_RESPONSE, &udp_handle_packet, this);
	m_dht->getNetwork()->networkingRegisterhandler( NET_PACKET_CRYPTO_HS, &udp_handle_packet, this);
	m_dht->getNetwork()->networkingRegisterhandler(NET_PACKET_CRYPTO_DATA, &udp_handle_packet, this);

	bs_list_init(&ip_port_list, sizeof(IP_Port), 8);
	return 0;
}

/* Return a random TCP connection number for use in send_tcp_onion_request.
 *
 * TODO: This number is just the index of an array that the elements can
 * change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int get_random_tcp_con_number(Net_Crypto* c)
{
	pthread_mutex_lock(&c->tcp_mutex);
	int ret = get_random_tcp_onion_conn_number(c->tcp_c);
	pthread_mutex_unlock(&c->tcp_mutex);

	return ret;
}

/* Send an onion packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int send_tcp_onion_request(Net_Crypto* c, unsigned int tcp_connections_number, const uint8_t* data, uint16_t length)
{
	pthread_mutex_lock(&c->tcp_mutex);
	int ret = tcp_send_onion_request(c->tcp_c, tcp_connections_number, data, length);
	pthread_mutex_unlock(&c->tcp_mutex);

	return ret;
}

/* Copy a maximum of num TCP relays we are connected to to tcp_relays.
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
unsigned int copy_connected_tcp_relays(Net_Crypto* c, Node_format* tcp_relays, uint16_t num)
{
	if (num == 0)
		return 0;

	pthread_mutex_lock(&c->tcp_mutex);
	unsigned int ret = tcp_copy_connected_relays(c->tcp_c, tcp_relays, num);
	pthread_mutex_unlock(&c->tcp_mutex);

	return ret;
}
