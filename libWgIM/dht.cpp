#include "dht.h"
#include "ping.h"

/*TODO: change this to 7 when done*/
#define HARDENING_ALL_OK 2

#define PACKED_NODE_SIZE_IP4 (1 + SIZE_IP4 + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES)
#define PACKED_NODE_SIZE_IP6 (1 + SIZE_IP6 + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES)

#define HARDREQ_DATA_SIZE 384 /* Attempt to prevent amplification/other attacks*/

#define CHECK_TYPE_ROUTE_REQ 0
#define CHECK_TYPE_ROUTE_RES 1
#define CHECK_TYPE_GETNODE_REQ 2
#define CHECK_TYPE_GETNODE_RES 3
#define CHECK_TYPE_TEST_REQ 4
#define CHECK_TYPE_TEST_RES 5


#define MAX_NORMAL_PUNCHING_TRIES 5

#define NAT_PING_REQUEST    0
#define NAT_PING_RESPONSE   1

/* Number of get node requests to send to quickly find close nodes. */
#define MAX_BOOTSTRAP_TIMES 5

#define HARDENING_INTERVAL 120
#define HARDEN_TIMEOUT 1200

/* return 0 if not.
 * return 1 if route request are ok
 * return 2 if it responds to send node packets correctly
 * return 4 if it can test other nodes correctly
 * return HARDENING_ALL_OK if all ok.
 */
static uint8_t hardening_correct(const Hardening* h)
{
	return h->routes_requests_ok + (h->send_nodes_ok << 1) + (h->testing_requests << 2);
}

static uint8_t cmp_public_key[crypto_box_PUBLICKEYBYTES];
static int cmp_dht_entry(const void* a, const void* b)
{
	Client_data entry1, entry2;
	memcpy(&entry1, a, sizeof(Client_data));
	memcpy(&entry2, b, sizeof(Client_data));
	int t1 = is_timeout(entry1.assoc4.timestamp, BAD_NODE_TIMEOUT) && is_timeout(entry1.assoc6.timestamp, BAD_NODE_TIMEOUT);
	int t2 = is_timeout(entry2.assoc4.timestamp, BAD_NODE_TIMEOUT) && is_timeout(entry2.assoc6.timestamp, BAD_NODE_TIMEOUT);

	if (t1 && t2)
		return 0;

	if (t1)
		return -1;

	if (t2)
		return 1;

	t1 = hardening_correct(&entry1.assoc4.hardening) != HARDENING_ALL_OK
		&& hardening_correct(&entry1.assoc6.hardening) != HARDENING_ALL_OK;
	t2 = hardening_correct(&entry2.assoc4.hardening) != HARDENING_ALL_OK
		&& hardening_correct(&entry2.assoc6.hardening) != HARDENING_ALL_OK;

	if (t1 != t2) {
		if (t1)
			return -1;

		if (t2)
			return 1;
	}

	int close = id_closest(cmp_public_key, entry1.public_key, entry2.public_key);

	if (close == 1)
		return 1;

	if (close == 2)
		return -1;

	return 0;
}


void to_net_family(IP* ip)
{
	if (ip->family == AF_INET)
		ip->family = TOX_AF_INET;
	else if (ip->family == AF_INET6)
		ip->family = TOX_AF_INET6;
}

int to_host_family(IP* ip)
{
	if (ip->family == TOX_AF_INET) {
		ip->family = AF_INET;
		return 0;
	}
	else if (ip->family == TOX_AF_INET6) {
		ip->family = AF_INET6;
		return 0;
	}
	else {
		return -1;
	}
}

/* Shared key generations are costly, it is therefor smart to store commonly used
 * ones so that they can re used later without being computed again.
 *
 * If shared key is already in shared_keys, copy it to shared_key.
 * else generate it into shared_key and copy it to shared_keys
 */
void get_shared_key(Shared_Keys* shared_keys, uint8_t* shared_key, const uint8_t* secret_key, const uint8_t* public_key)
{
	uint32_t i, num = ~0, curr = 0;

	for (i = 0; i < MAX_KEYS_PER_SLOT; ++i) {
		int index = public_key[30] * MAX_KEYS_PER_SLOT + i;

		if (shared_keys->keys[index].stored) {
			if (CryptoCore::publicKeyCmp(public_key, shared_keys->keys[index].public_key) == 0) {
				memcpy(shared_key, shared_keys->keys[index].shared_key, crypto_box_BEFORENMBYTES);
				++shared_keys->keys[index].times_requested;
				shared_keys->keys[index].time_last_requested = unix_time();
				return;
			}

			if (num != 0) {
				if (is_timeout(shared_keys->keys[index].time_last_requested, KEYS_TIMEOUT)) {
					num = 0;
					curr = index;
				}
				else if (num > shared_keys->keys[index].times_requested) {
					num = shared_keys->keys[index].times_requested;
					curr = index;
				}
			}
		}
		else {
			if (num != 0) {
				num = 0;
				curr = index;
			}
		}
	}

	CryptoCore::encryptPrecompute(public_key, secret_key, shared_key);

	if (num != (uint32_t)~0) {
		shared_keys->keys[curr].stored = 1;
		shared_keys->keys[curr].times_requested = 1;
		memcpy(shared_keys->keys[curr].public_key, public_key, crypto_box_PUBLICKEYBYTES);
		memcpy(shared_keys->keys[curr].shared_key, shared_key, crypto_box_BEFORENMBYTES);
		shared_keys->keys[curr].time_last_requested = unix_time();
	}
}


/* Check if client with public_key is already in list of length length.If it is then set its corresponding timestamp to current time.
 * If the id is already in the list with a different ip_port, update it.  TODO: Maybe optimize this. *  return True(1) or False(0)
 *检查带有public_key的客户端是否已经在长度列表中。如果是，则将其相应的时间戳设置为当前时间。 
 *如果id已经在列表中使用不同的ip_port，请更新它。 TODO：也许优化这个。
 */
static int client_or_ip_port_in_list(Client_data* list, uint16_t length, const uint8_t* public_key, IP_Port ip_port)
{
	uint32_t i;
	uint64_t temp_time = unix_time();

	/* if public_key is in list, find it and maybe overwrite ip_port */
	for (i = 0; i < length; ++i)
		if (id_equal(list[i].public_key, public_key)) {
			/* Refresh the client timestamp. */
			if (ip_port.ip.family == AF_INET)
			{

				if (!ipport_equal(&list[i].assoc4.ip_port, &ip_port)) 
				{					
					ip_ntoa(&list[i].assoc4.ip_port.ip);
					ntohs(list[i].assoc4.ip_port.port);
					ip_ntoa(&ip_port.ip), ntohs(ip_port.port);
				}				

				if (LAN_ip(list[i].assoc4.ip_port.ip) != 0 && LAN_ip(ip_port.ip) == 0)
					return 1;

				list[i].assoc4.ip_port = ip_port;
				list[i].assoc4.timestamp = temp_time;
			}
			else if (ip_port.ip.family == AF_INET6) {

				if (!ipport_equal(&list[i].assoc4.ip_port, &ip_port)) 
				{
					
					ip_ntoa(&list[i].assoc6.ip_port.ip);
					ntohs(list[i].assoc6.ip_port.port);
					ip_ntoa(&ip_port.ip); 
					ntohs(ip_port.port);
				}
			

				if (LAN_ip(list[i].assoc6.ip_port.ip) != 0 && LAN_ip(ip_port.ip) == 0)
					return 1;

				list[i].assoc6.ip_port = ip_port;
				list[i].assoc6.timestamp = temp_time;
			}

			return 1;
		}

	/* public_key not in list yet: see if we can find an identical ip_port, in that case we kill the old public_key by overwriting it with the new one
	 * public_key尚未在列表中：看看我们是否可以找到相同的ip_port，在这种情况下，我们通过用新的public_key覆盖它来杀死旧的public_key。
	 * TODO: maybe we SHOULDN'T do that if that public_key is in a friend_list and the one who is the actual friend's public_key/address set? 
	 * 如果public_key在friend_list中，我们也许不应该这样做*/
	for (i = 0; i < length; ++i) {
		/* MAYBE: check the other address, if valid, don't nuke? */
		if ((ip_port.ip.family == AF_INET) && ipport_equal(&list[i].assoc4.ip_port, &ip_port)) {
			/* Initialize client timestamp. */
			list[i].assoc4.timestamp = temp_time;
			memcpy(list[i].public_key, public_key, crypto_box_PUBLICKEYBYTES);			

			/* kill the other address, if it was set */
			memset(&list[i].assoc6, 0, sizeof(list[i].assoc6));
			return 1;
		}
		else if ((ip_port.ip.family == AF_INET6) && ipport_equal(&list[i].assoc6.ip_port, &ip_port)) {
			/* Initialize client timestamp. */
			list[i].assoc6.timestamp = temp_time;
			memcpy(list[i].public_key, public_key, crypto_box_PUBLICKEYBYTES);			

			/* kill the other address, if it was set */
			memset(&list[i].assoc4, 0, sizeof(list[i].assoc4));
			return 1;
		}
	}

	return 0;
}

/* Is it ok to store node with public_key in client.
 *
 * return 0 if node can't be stored.
 * return 1 if it can.
 */
static unsigned int store_node_ok(const Client_data* client, const uint8_t* public_key, const uint8_t* comp_public_key)
{
	if ((is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT) && is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT))
		|| (id_closest(comp_public_key, client->public_key, public_key) == 2)) {
		return 1;
	}
	else {
		return 0;
	}
}

static void sort_client_list(Client_data* list, unsigned int length, const uint8_t* comp_public_key)
{
	memcpy(cmp_public_key, comp_public_key, crypto_box_PUBLICKEYBYTES);
	qsort(list, length, sizeof(Client_data), cmp_dht_entry);
}

/* Return index of first unequal bit number.
 */
static unsigned int bit_by_bit_cmp(const uint8_t* pk1, const uint8_t* pk2)
{
	unsigned int i, j = 0;

	for (i = 0; i < crypto_box_PUBLICKEYBYTES; ++i) {
		if (pk1[i] == pk2[i])
			continue;

		for (j = 0; j < 8; ++j) {
			if ((pk1[i] & (1 << (7 - j))) != (pk2[i] & (1 << (7 - j))))
				break;
		}

		break;
	}

	return i * 8 + j;
}



/* Replace a first bad (or empty) node with this one or replace a possibly bad node (tests failed or not done yet)
 *  that is further than any other in the list from the comp_public_key or replace a good node that is further
 *  than any other in the list from the comp_public_key  and further than public_key.
 *用这个替换第一个坏（或空）节点或者替换可能是坏节点（测试失败或尚未完成），这个节点比comp_public_key中列表中的任何其他节点更远
  *或者从comp_public_key中取代比列表中任何其他节点更好的节点，而不是public_key。
 * Do not replace any node if the list has no bad or possibly bad nodes and all nodes in the list are closer to comp_public_key
 *  than public_key.
 *如果列表没有坏节点或可能坏节点并且列表中的所有节点都比public_key更接近comp_public_key，则不要替换任何节点。
 *  returns True(1) when the item was stored, False(0) otherwise */
static int replace_all(Client_data* list,	uint16_t  length,const uint8_t* public_key,IP_Port  ip_port,const uint8_t* comp_public_key)
{
	if ((ip_port.ip.family != AF_INET) && (ip_port.ip.family != AF_INET6))
		return 0;

	if (store_node_ok(&list[1], public_key, comp_public_key) || store_node_ok(&list[0], public_key, comp_public_key)) {
		sort_client_list(list, length, comp_public_key);

		IPPTsPng* ipptp_write = NULL;
		IPPTsPng* ipptp_clear = NULL;

		Client_data* client = &list[0];

		if (ip_port.ip.family == AF_INET) {
			ipptp_write = &client->assoc4;
			ipptp_clear = &client->assoc6;
		}
		else {
			ipptp_write = &client->assoc6;
			ipptp_clear = &client->assoc4;
		}

		id_copy(client->public_key, public_key);
		ipptp_write->ip_port = ip_port;
		ipptp_write->timestamp = unix_time();

		ip_reset(&ipptp_write->ret_ip_port.ip);
		ipptp_write->ret_ip_port.port = 0;
		ipptp_write->ret_timestamp = 0;

		/* zero out other address */
		memset(ipptp_clear, 0, sizeof(*ipptp_clear));

		return 1;
	}

	return 0;
}

/* Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked nodes on success.
 * return -1 on failure.
 */
int unpack_nodes(Node_format* nodes, uint16_t max_num_nodes, uint16_t* processed_data_len, const uint8_t* data,
	uint16_t length, uint8_t tcp_enabled)
{
	uint32_t num = 0, len_processed = 0;

	while (num < max_num_nodes && len_processed < length) {
		int ipv6 = -1;
		uint8_t host_family;

		if (data[len_processed] == TOX_AF_INET) {
			ipv6 = 0;
			host_family = AF_INET;
		}
		else if (data[len_processed] == TOX_TCP_INET) {
			if (!tcp_enabled)
				return -1;

			ipv6 = 0;
			host_family = TCP_INET;
		}
		else if (data[len_processed] == TOX_AF_INET6) {
			ipv6 = 1;
			host_family = AF_INET6;
		}
		else if (data[len_processed] == TOX_TCP_INET6) {
			if (!tcp_enabled)
				return -1;

			ipv6 = 1;
			host_family = TCP_INET6;
		}
		else {
			return -1;
		}

		if (ipv6 == 0) {
			uint32_t size = PACKED_NODE_SIZE_IP4;

			if (len_processed + size > length)
				return -1;

			nodes[num].ip_port.ip.family = host_family;
			memcpy(&nodes[num].ip_port.ip.ip4, data + len_processed + 1, SIZE_IP4);
			memcpy(&nodes[num].ip_port.port, data + len_processed + 1 + SIZE_IP4, sizeof(uint16_t));
			memcpy(nodes[num].public_key, data + len_processed + 1 + SIZE_IP4 + sizeof(uint16_t), crypto_box_PUBLICKEYBYTES);
			len_processed += size;
			++num;
		}
		else if (ipv6 == 1) {
			uint32_t size = PACKED_NODE_SIZE_IP6;

			if (len_processed + size > length)
				return -1;

			nodes[num].ip_port.ip.family = host_family;
			memcpy(&nodes[num].ip_port.ip.ip6, data + len_processed + 1, SIZE_IP6);
			memcpy(&nodes[num].ip_port.port, data + len_processed + 1 + SIZE_IP6, sizeof(uint16_t));
			memcpy(nodes[num].public_key, data + len_processed + 1 + SIZE_IP6 + sizeof(uint16_t), crypto_box_PUBLICKEYBYTES);
			len_processed += size;
			++num;
		}
		else {
			return -1;
		}
	}

	if (processed_data_len)
		* processed_data_len = len_processed;

	return num;
}


static int handle_getnodes(void* object, IP_Port source, const uint8_t* packet, uint16_t length)
{
	if (length != (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + sizeof(uint64_t) + crypto_box_MACBYTES))
		return 1;

	DHT * dht = (DHT*)object;

	/* Check if packet is from ourself. */
	if (id_equal(packet + 1, dht->selfPublicKey()))
		return 1;

	uint8_t plain[crypto_box_PUBLICKEYBYTES + sizeof(uint64_t)];
	uint8_t shared_key[crypto_box_BEFORENMBYTES];

	dht->getSharedKeyRecv(shared_key, packet + 1);
	int len = CryptoCore::decryptDataSymmetric(shared_key,	packet + 1 + crypto_box_PUBLICKEYBYTES,packet + 1 + crypto_box_PUBLICKEYBYTES 
		+ crypto_box_NONCEBYTES,	crypto_box_PUBLICKEYBYTES + sizeof(uint64_t) + crypto_box_MACBYTES,	plain);

	if (len != crypto_box_PUBLICKEYBYTES + sizeof(uint64_t))
		return 1;

	 dht->sendnodes_ipv6(source, packet + 1, plain, plain + crypto_box_PUBLICKEYBYTES, sizeof(uint64_t), shared_key);	
	 dht->getPing()->addToPing(packet + 1, source);
	return 0;
}

/* Check if client with public_key is already in node format list of length length.
 *检查具有public_key的客户端是否已经是length长度的节点格式列表。
 *  return 1 if true.
 *  return 0 if false. */
static int client_in_nodelist(const Node_format* list, uint16_t length, const uint8_t* public_key)
{
	uint32_t i;
	for (i = 0; i < length; ++i) {
		if (id_equal(list[i].public_key, public_key))
			return 1;
	}
	return 0;
}


/* Add node to the node list making sure only the nodes closest to cmp_pk are in the list.
 */
bool add_to_list(Node_format* nodes_list, unsigned int length, const uint8_t* pk, IP_Port ip_port,	const uint8_t* cmp_pk)
{
	uint8_t pk_bak[crypto_box_PUBLICKEYBYTES];
	IP_Port ip_port_bak;

	unsigned int i;

	for (i = 0; i < length; ++i) {
		if (id_closest(cmp_pk, nodes_list[i].public_key, pk) == 2) {
			memcpy(pk_bak, nodes_list[i].public_key, crypto_box_PUBLICKEYBYTES);
			ip_port_bak = nodes_list[i].ip_port;
			memcpy(nodes_list[i].public_key, pk, crypto_box_PUBLICKEYBYTES);
			nodes_list[i].ip_port = ip_port;

			if (i != (length - 1))
				add_to_list(nodes_list, length, pk_bak, ip_port_bak, cmp_pk);

			return 1;
		}
	}
	return 0;
}



/*
 * helper for get_close_nodes(). argument list is a monster :D
 */
static void get_close_nodes_inner(const uint8_t* public_key, Node_format* nodes_list,	sa_family_t sa_family, const Client_data* client_list, 
	uint32_t client_list_length,	uint32_t* num_nodes_ptr, uint8_t is_LAN, uint8_t want_good)
{
	if ((sa_family != AF_INET) && (sa_family != AF_INET6) && (sa_family != 0))
		return;

	uint32_t num_nodes = *num_nodes_ptr;
	uint32_t i;

	for (i = 0; i < client_list_length; i++) {
		const Client_data* client = &client_list[i];

		/* node already in list? */
		if (client_in_nodelist(nodes_list, MAX_SENT_NODES, client->public_key))
			continue;

		const IPPTsPng* ipptp = NULL;

		if (sa_family == AF_INET) {
			ipptp = &client->assoc4;
		}
		else if (sa_family == AF_INET6) {
			ipptp = &client->assoc6;
		}
		else {
			if (client->assoc4.timestamp >= client->assoc6.timestamp) {
				ipptp = &client->assoc4;
			}
			else {
				ipptp = &client->assoc6;
			}
		}

		/* node not in a good condition? */
		if (is_timeout(ipptp->timestamp, BAD_NODE_TIMEOUT))
			continue;

		/* don't send LAN ips to non LAN peers */
		if (LAN_ip(ipptp->ip_port.ip) == 0 && !is_LAN)
			continue;

		if (LAN_ip(ipptp->ip_port.ip) != 0 && want_good && hardening_correct(&ipptp->hardening) != HARDENING_ALL_OK
			&& !id_equal(public_key, client->public_key))
			continue;

		if (num_nodes < MAX_SENT_NODES) {
			memcpy(nodes_list[num_nodes].public_key,
				client->public_key,
				crypto_box_PUBLICKEYBYTES);

			nodes_list[num_nodes].ip_port = ipptp->ip_port;
			num_nodes++;
		}
		else {
			add_to_list(nodes_list, MAX_SENT_NODES, client->public_key, ipptp->ip_port, public_key);
		}
	}
	*num_nodes_ptr = num_nodes;
}


/* Pack number of nodes into data of maxlength length.
 *
 * return length of packed nodes on success.
 * return -1 on failure.
 */
int pack_nodes(uint8_t* data, uint16_t length, const Node_format* nodes, uint16_t number)
{
	uint32_t i, packed_length = 0;

	for (i = 0; i < number; ++i) {
		int ipv6 = -1;
		uint8_t net_family;

		// FIXME use functions to convert endianness
		if (nodes[i].ip_port.ip.family == AF_INET) {
			ipv6 = 0;
			net_family = TOX_AF_INET;
		}
		else if (nodes[i].ip_port.ip.family == TCP_INET) {
			ipv6 = 0;
			net_family = TOX_TCP_INET;
		}
		else if (nodes[i].ip_port.ip.family == AF_INET6) {
			ipv6 = 1;
			net_family = TOX_AF_INET6;
		}
		else if (nodes[i].ip_port.ip.family == TCP_INET6) {
			ipv6 = 1;
			net_family = TOX_TCP_INET6;
		}
		else {
			return -1;
		}

		if (ipv6 == 0) {
			uint32_t size = PACKED_NODE_SIZE_IP4;

			if (packed_length + size > length)
				return -1;

			data[packed_length] = net_family;
			memcpy(data + packed_length + 1, &nodes[i].ip_port.ip.ip4, SIZE_IP4);
			memcpy(data + packed_length + 1 + SIZE_IP4, &nodes[i].ip_port.port, sizeof(uint16_t));
			memcpy(data + packed_length + 1 + SIZE_IP4 + sizeof(uint16_t), nodes[i].public_key, crypto_box_PUBLICKEYBYTES);
			packed_length += size;
		}
		else if (ipv6 == 1) {
			uint32_t size = PACKED_NODE_SIZE_IP6;

			if (packed_length + size > length)
				return -1;

			data[packed_length] = net_family;
			memcpy(data + packed_length + 1, &nodes[i].ip_port.ip.ip6, SIZE_IP6);
			memcpy(data + packed_length + 1 + SIZE_IP6, &nodes[i].ip_port.port, sizeof(uint16_t));
			memcpy(data + packed_length + 1 + SIZE_IP6 + sizeof(uint16_t), nodes[i].public_key, crypto_box_PUBLICKEYBYTES);
			packed_length += size;
		}
		else {
			return -1;
		}
	}
	return packed_length;
}


static int handle_sendnodes_core(void* object, IP_Port source, const uint8_t* packet, uint16_t length,
	Node_format* plain_nodes, uint16_t size_plain_nodes, uint32_t* num_nodes_out)
{
	DHT* dht = (DHT*)object;
	uint32_t cid_size = 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + 1 + sizeof(uint64_t) + crypto_box_MACBYTES;

	if (length < cid_size) /* too short */
		return 1;

	uint32_t data_size = length - cid_size;

	if (data_size == 0)
		return 1;

	if (data_size > sizeof(Node_format) * MAX_SENT_NODES) /* invalid length */
		return 1;

	uint8_t* plain = new uint8_t[sizeof(uint64_t)+1 + data_size];
	uint8_t shared_key[crypto_box_BEFORENMBYTES];
	 dht->getSharedKeySent (shared_key, packet + 1);
	int len = CryptoCore::decryptDataSymmetric(shared_key,	packet + 1 + crypto_box_PUBLICKEYBYTES,
		packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,	1 + data_size + sizeof(uint64_t) + crypto_box_MACBYTES,plain);

	if ((unsigned int)len != sizeof(plain))
	{
		delete[]plain;
		return 1;
	}
		

	if (plain[0] > size_plain_nodes)
	{
		delete[]plain;
		return 1;
	}

	Node_format sendback_node;
	uint64_t ping_id;
	memcpy(&ping_id, plain + 1 + data_size, sizeof(ping_id));

	if (!dht->    sent_getnode_to_node(packet + 1, source, ping_id, &sendback_node))
	{
		delete[]plain;
		return 1;
	}

	uint16_t length_nodes = 0;
	int num_nodes = unpack_nodes(plain_nodes, plain[0], &length_nodes, plain + 1, data_size, 0);

	if (length_nodes != data_size)
	{
		delete[]plain;
		return 1;
	}

	if (num_nodes != plain[0])
	{
		delete[]plain;
		return 1;
	}

	if (num_nodes < 0)
	{
		delete[]plain;
		return 1;
	}

	/* store the address the *request* was sent to */
	dht->addtoLists (source, packet + 1);

	*num_nodes_out = num_nodes;

	 dht->send_hardening_getnode_res(&sendback_node, packet + 1, plain + 1, data_size);	
	delete[]plain;	
	return 0;
}

static int handle_sendnodes_ipv6(void* object, IP_Port source, const uint8_t* packet, uint16_t length)
{
	DHT* dht =(DHT *) object;
	Node_format plain_nodes[MAX_SENT_NODES];
	uint32_t num_nodes;

	if (handle_sendnodes_core(object, source, packet, length, plain_nodes, MAX_SENT_NODES, &num_nodes))
		return 1;

	if (num_nodes == 0)
		return 0;

	uint32_t i;

	for (i = 0; i < num_nodes; i++) {

		if (ipport_isset(&plain_nodes[i].ip_port)) {
			dht->ping_node_from_getnodes_ok( plain_nodes[i].public_key, plain_nodes[i].ip_port);
			dht->returnedip_ports(plain_nodes[i].ip_port, plain_nodes[i].public_key, packet + 1);
		}
	}

	return 0;
}

static bool is_pk_in_client_list(Client_data* list, unsigned int client_list_length, const uint8_t* public_key,	IP_Port ip_port)
{
	unsigned int i;

	for (i = 0; i < client_list_length; ++i) {
		if ((ip_port.ip.family == AF_INET && !is_timeout(list[i].assoc4.timestamp, BAD_NODE_TIMEOUT))
			|| (ip_port.ip.family == AF_INET6 && !is_timeout(list[i].assoc6.timestamp, BAD_NODE_TIMEOUT))) {
			if (CryptoCore::publicKeyCmp(list[i].public_key, public_key) == 0) {
				return 1;
			}
		}
	}

	return 0;
}

static int cryptopacket_handle(void* object, IP_Port source, const uint8_t* packet, uint16_t length)
{
	DHT* dht = (DHT*)object;

	if (packet[0] == NET_PACKET_CRYPTO) {
		if (length <= crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + 1 + crypto_box_MACBYTES ||
			length > MAX_CRYPTO_REQUEST_SIZE + crypto_box_MACBYTES)
			return 1;

		if ( CryptoCore::publicKeyCmp(packet + 1, dht->selfPublicKey()) == 0) { // Check if request is for us.
			uint8_t public_key[crypto_box_PUBLICKEYBYTES];
			uint8_t data[MAX_CRYPTO_REQUEST_SIZE];
			uint8_t number;
			int len =CryptoCore::handle_request(dht->selfPublicKey(), dht->selfSecretKey(), public_key, data, &number, packet, length);

			if (len == -1 || len == 0)
				return 1;

			if (!dht->cryptopackethandlers()[number].function)  return 1;

			return dht->cryptopackethandlers()[number].function(dht->cryptopackethandlers()[number].object, source, public_key,	data, len);
		}
		else { /* If request is not for us, try routing it. */
			int retval = dht->route_packet(packet + 1, packet, length);

			if ((unsigned int)retval == length)
				return 0;
		}
	}
	return 1;
}


/* Handle a received ping request for. 处理收到的ping请求*/
static int handle_NATping(void* object, IP_Port source, const uint8_t* source_pubkey, const uint8_t* packet,	uint16_t length)
{
	if (length != sizeof(uint64_t) + 1)
		return 1;

	DHT * dht = (DHT*)object;
	uint64_t ping_id;
	memcpy(&ping_id, packet + 1, sizeof(uint64_t));

	int friendnumber = dht->friend_number(source_pubkey);

	if (friendnumber == -1)
		return 1;

	DHT_Friend * friend1 = & dht->friendsList()[friendnumber];

	if (packet[0] == NAT_PING_REQUEST) {
		/* 1 is reply */
		dht->send_NATping( source_pubkey, ping_id, NAT_PING_RESPONSE);
		friend1->nat.recvNATping_timestamp = unix_time();
		return 0;
	}
	else if (packet[0] == NAT_PING_RESPONSE) {
		if (friend1->nat.NATping_id == ping_id) {
			friend1->nat.NATping_id = random_64b();
			friend1->nat.hole_punching = 1;
			return 0;
		}
	}

	return 1;
}


/* Handle a received hardening packet 处理收到的加固数据包*/
static int handle_hardening(void* object, IP_Port source, const uint8_t* source_pubkey, const uint8_t* packet,	uint16_t length)
{
	DHT* dht =(DHT*) object;

	if (length < 2) {
		return 1;
	}

	switch (packet[0]) {
	case CHECK_TYPE_GETNODE_REQ: {
		if (length != HARDREQ_DATA_SIZE)
			return 1;

		Node_format node, tocheck_node;
		node.ip_port = source;
		memcpy(node.public_key, source_pubkey, crypto_box_PUBLICKEYBYTES);
		memcpy(&tocheck_node, packet + 1, sizeof(Node_format));

		if (dht->getnodes(tocheck_node.ip_port, tocheck_node.public_key, packet + 1 + sizeof(Node_format), &node) == -1)
			return 1;

		return 0;
	}

	case CHECK_TYPE_GETNODE_RES: {
		if (length <= crypto_box_PUBLICKEYBYTES + 1)
			return 1;

		if (length > 1 + crypto_box_PUBLICKEYBYTES + sizeof(Node_format) * MAX_SENT_NODES)
			return 1;

		uint16_t length_nodes = length - 1 - crypto_box_PUBLICKEYBYTES;
		Node_format nodes[MAX_SENT_NODES];
		int num_nodes = unpack_nodes(nodes, MAX_SENT_NODES, 0, packet + 1 + crypto_box_PUBLICKEYBYTES, length_nodes, 0);

		/* TODO: MAX_SENT_NODES nodes should be returned at all times
		 (right now we have a small network size so it could cause problems for testing and etc..) */
		if (num_nodes <= 0)
			return 1;

		/* NOTE: This should work for now but should be changed to something better. */
		if (dht->have_nodes_closelist(nodes, num_nodes) < (uint32_t)((num_nodes + 2) / 2))
			return 1;

		IPPTsPng * temp = dht->get_closelist_IPPTsPng(packet + 1, nodes[0].ip_port.ip.family);

		if (temp == NULL)
			return 1;

		if (is_timeout(temp->hardening.send_nodes_timestamp, HARDENING_INTERVAL))
			return 1;

		if (CryptoCore::publicKeyCmp(temp->hardening.send_nodes_pingedid, source_pubkey) != 0)
			return 1;

		/* If Nodes look good and the request checks out */
		temp->hardening.send_nodes_ok = 1;
		return 0;/* success*/
	}
	}

	return 1;
}


DHT::DHT(QObject *parent)	: QObject(parent)
{
	Utiliy::unixTimeUpdate();
}

DHT::~DHT()
{
}

int DHT::init(std::shared_ptr<Networking_Core> net)
{
	m_net = net;
	m_ping = new Ping;
	m_ping->init( static_cast<std::shared_ptr<DHT>>( this));

	
	m_net->networkingRegisterhandler(NET_PACKET_GET_NODES, &handle_getnodes, this);
	m_net->networkingRegisterhandler(NET_PACKET_SEND_NODES_IPV6, &handle_sendnodes_ipv6, this);
	m_net->networkingRegisterhandler(NET_PACKET_CRYPTO, &cryptopacket_handle, this);
	cryptopacket_registerhandler(CRYPTO_PACKET_NAT_PING, &handle_NATping, this);
	cryptopacket_registerhandler(CRYPTO_PACKET_HARDENING, &handle_hardening, this);

	CryptoCore::new_symmetric_key(m_secretSymmetric_key);
	crypto_box_keypair(m_selfPublicKey,m_selfSecretKey);

	ping_array_init(&m_dhtPingArray, DHT_PING_ARRAY_SIZE, PING_TIMEOUT);
	ping_array_init(&m_dhtHardenPingArray, DHT_PING_ARRAY_SIZE, PING_TIMEOUT);
	
	for (uint32_t i = 0; i < DHT_FAKE_FRIEND_NUMBER; ++i)
	{
		uint8_t random_key_bytes[crypto_box_PUBLICKEYBYTES]{};
		randombytes(random_key_bytes, sizeof(random_key_bytes));

		if (addfriend(random_key_bytes, 0, 0, 0, 0) != 0)
		{			
			return 1;
		}
	}
	return 0;
}


/* Shared key generations are costly, it is therefor smart to store commonly used
 * ones so that they can re used later without being computed again.
 *共享密钥生成是昂贵的，因此存储常用的密钥使得它们可以在以后重新使用而不再被计算。
 * If shared key is already in shared_keys, copy it to shared_key.
 * else generate it into shared_key and copy it to shared_keys
 *如果共享密钥已在shared_keys中，请将其复制到shared_key。 否则将其生成为shared_key并将其复制到shared_keys*/
void DHT::getSharedKey(Shared_Keys* shared_keys, uint8_t* shared_key, const uint8_t* secret_key, const uint8_t* public_key)
{
	uint32_t i, num = ~0, curr = 0;

	for (i = 0; i < MAX_KEYS_PER_SLOT; ++i)
	{
		int index = public_key[30] * MAX_KEYS_PER_SLOT + i;

		if (shared_keys->keys[index].stored) 
		{
			if ( CryptoCore::publicKeyCmp(public_key, shared_keys->keys[index].public_key) == 0)
			{
				memcpy(shared_key, shared_keys->keys[index].shared_key, crypto_box_BEFORENMBYTES);
				++shared_keys->keys[index].times_requested;
				shared_keys->keys[index].time_last_requested = unix_time();
				return;
			}

			if (num != 0) 
			{
				if (is_timeout(shared_keys->keys[index].time_last_requested, KEYS_TIMEOUT)) 
				{
					num = 0;
					curr = index;
				}
				else if (num > shared_keys->keys[index].times_requested) 
				{
					num = shared_keys->keys[index].times_requested;
					curr = index;
				}
			}
		}
		else 
		{
			if (num != 0)
			{
				num = 0;
				curr = index;
			}
		}
	}

	CryptoCore::encryptPrecompute(public_key, secret_key, shared_key);

	if (num != (uint32_t)~0) {
		shared_keys->keys[curr].stored = 1;
		shared_keys->keys[curr].times_requested = 1;
		memcpy(shared_keys->keys[curr].public_key, public_key, crypto_box_PUBLICKEYBYTES);
		memcpy(shared_keys->keys[curr].shared_key, shared_key, crypto_box_BEFORENMBYTES);
		shared_keys->keys[curr].time_last_requested = unix_time();
	}
}


/* Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_keyfor packets that we send
 * .复制shared_key以将来自public_key的DHT数据包加密/解密为我们发送的数据包的shared_key。
 */
void DHT::getSharedKeySent(uint8_t* shared_key, const uint8_t* public_key)
{
	getSharedKey(&m_sharedKeysSent, shared_key, m_selfSecretKey, public_key);
}


/* Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_key for packets that we receive.
 * 复制shared_key以将来自public_key的DHT数据包加密/解密为我们收到的数据包的shared_key。
 */
void DHT::getSharedKeyRecv(uint8_t* shared_key, const uint8_t* public_key)
{
	getSharedKey(&m_sharedKeysRecv, shared_key, m_selfSecretKey, public_key);
}


/* Return 1 if node can be added to close list, 0 if it can't.
 */
bool DHT::nodeAddableToCloseList( const uint8_t* public_key, IP_Port ip_port)
{
	if (addToClose( public_key, ip_port, 1) == 0) {
		return 1;
	}
	return 0;
}

/* Add node to close list. simulate is set to 1 if we want to check if a node can be added to the list without adding it.
 *将节点添加到关闭列表。 如果我们想要检查节点是否可以添加到列表而不添加它，则将simulate设置为1。
 *  return -1 on failure. * return 0 on success. */
 int DHT::addToClose( const uint8_t* public_key, IP_Port ip_port, bool simulate)
{
	unsigned int i;

	unsigned int index = bitByBitCmp(public_key, m_selfPublicKey);

	if (index > LCLIENT_LENGTH)
		index = LCLIENT_LENGTH - 1;

	for (i = 0; i < LCLIENT_NODES; ++i) {
		Client_data* client = &m_closeClientlist[(index * LCLIENT_NODES) + i];

		if (is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT) && is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT)) {
			if (!simulate) {
				IPPTsPng* ipptp_write = NULL;
				IPPTsPng* ipptp_clear = NULL;

				if (ip_port.ip.family == AF_INET) {
					ipptp_write = &client->assoc4;
					ipptp_clear = &client->assoc6;
				}
				else {
					ipptp_write = &client->assoc6;
					ipptp_clear = &client->assoc4;
				}

				id_copy(client->public_key, public_key);
				ipptp_write->ip_port = ip_port;
				ipptp_write->timestamp = unix_time();

				ip_reset(&ipptp_write->ret_ip_port.ip);
				ipptp_write->ret_ip_port.port = 0;
				ipptp_write->ret_timestamp = 0;

				/* zero out other address */
				memset(ipptp_clear, 0, sizeof(*ipptp_clear));
			}
			return 0;
		}
	}
	return -1;
}


 /* Return index of first unequal bit number.
 */
 unsigned int DHT::bitByBitCmp(const uint8_t* pk1, const uint8_t* pk2)
 {
	 unsigned int i, j = 0;

	 for (i = 0; i < crypto_box_PUBLICKEYBYTES; ++i) {
		 if (pk1[i] == pk2[i])
			 continue;

		 for (j = 0; j < 8; ++j) {
			 if ((pk1[i] & (1 << (7 - j))) != (pk2[i] & (1 << (7 - j))))
				 break;
		 }
		 break;
	 }
	 return i * 8 + j;
 }


 /* TODO: Optimize this. */
 int DHT::getfriendip(const uint8_t* public_key, IP_Port* ip_port)
 {
	 uint32_t i, j;
	 ip_reset(&ip_port->ip);
	 ip_port->port = 0;
	 for (i = 0; i < m_numFriends; ++i) {
		 /* Equal */
		 if (id_equal(m_friendsList[i].public_key, public_key)) {
			 for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
				 Client_data* client = &m_friendsList[i].client_list[j];

				 if (id_equal(client->public_key, public_key)) {
					 IPPTsPng* assoc = NULL;
					 uint32_t a;
					 for (a = 0, assoc = &client->assoc6; a < 2; a++, assoc = &client->assoc4)
						 if (!is_timeout(assoc->timestamp, BAD_NODE_TIMEOUT)) {
							 *ip_port = assoc->ip_port;
							 return 1;
						 }
				 }
			 }
			 return 0;
		 }
	 }
	 return -1;
 }

 /* Add node to the node list making sure only the nodes closest to cmp_pk are in the list.
 *将节点添加到节点列表，确保只有最接近cmp_pk的节点在列表中。
 */
 bool DHT::addToList(Node_format* nodes_list, unsigned int length, const uint8_t* pk, IP_Port ip_port, const uint8_t* cmp_pk)
 {
	 uint8_t pk_bak[crypto_box_PUBLICKEYBYTES];
	 IP_Port ip_port_bak;

	 unsigned int i;

	 for (i = 0; i < length; ++i) {
		 if (id_closest(cmp_pk, nodes_list[i].public_key, pk) == 2) {
			 memcpy(pk_bak, nodes_list[i].public_key, crypto_box_PUBLICKEYBYTES);
			 ip_port_bak = nodes_list[i].ip_port;
			 memcpy(nodes_list[i].public_key, pk, crypto_box_PUBLICKEYBYTES);
			 nodes_list[i].ip_port = ip_port;

			 if (i != (length - 1))
				 addToList(nodes_list, length, pk_bak, ip_port_bak, cmp_pk);

			 return 1;
		 }
	 }

	 return 0;
 }



 /* Attempt to add client with ip_port and public_key to the friends client list
 * and close_clientlist.returns 1+ if the item is used in any list, 0 else
 *尝试将带有ip_port和public_key的客户端添加到朋友客户端列表和close_clientlist。
 */
 int DHT::addtoLists(IP_Port ip_port, const uint8_t* public_key)
 {
	 uint32_t i, used = 0;

	 /* convert IPv4-in-IPv6 to IPv4 */
	 if ((ip_port.ip.family == AF_INET6) && IPV6_IPV4_IN_V6(ip_port.ip.ip6)) {
		 ip_port.ip.family = AF_INET;
		 ip_port.ip.ip4.uint32 = ip_port.ip.ip6.uint32[3];
	 }

	 /* NOTE: Current behavior if there are two clients with the same id is
	  * to replace the first ip by the second.
	  */
	 if (!client_or_ip_port_in_list(m_closeClientlist , LCLIENT_LIST, public_key, ip_port)) 
	 {
		 if  (addToClose (public_key, ip_port, 0))
			 used++;
	 }
	 else
		 used++;

	 DHT_Friend* friend_foundip = 0;

	 for (i = 0; i <m_numFriends; ++i) {
		 if (!client_or_ip_port_in_list(m_friendsList[i].client_list, MAX_FRIEND_CLIENTS, public_key, ip_port)) 
		 {
			 if (replace_all(m_friendsList[i].client_list, MAX_FRIEND_CLIENTS,
				 public_key, ip_port, m_friendsList[i].public_key))
			 {

				 DHT_Friend* dhtFriend = &m_friendsList[i];

				 if (CryptoCore::publicKeyCmp(public_key, dhtFriend->public_key) == 0) {
					 friend_foundip = dhtFriend;
				 }

				 used++;
			 }
		 }
		 else {
			 DHT_Friend* dhtFriend = &m_friendsList[i];

			 if (CryptoCore::publicKeyCmp(public_key, dhtFriend->public_key) == 0) {
				 friend_foundip = dhtFriend;
			 }

			 used++;
		 }
	 }

	 if (friend_foundip) {
		 uint32_t j;

		 for (j = 0; j < friend_foundip->lock_count; ++j) {
			 if (friend_foundip->callbacks[j].ip_callback)
				 friend_foundip->callbacks[j].ip_callback(friend_foundip->callbacks[j].data, friend_foundip->callbacks[j].number,
					 ip_port);
		 }
	 }

#ifdef ENABLE_ASSOC_DHT

	 if (dht->assoc) {
		 IPPTs ippts;

		 ippts.ip_port = ip_port;
		 ippts.timestamp = unix_time();

		 Assoc_add_entry(dht->assoc, public_key, &ippts, NULL, used ? 1 : 0);
	 }

#endif
	 return used;
 }


 /* Send a send nodes response: message for IPv6 nodes 发送一发送节点响应：IPv6节点的消息*/
 int DHT::sendnodes_ipv6(IP_Port ip_port, const uint8_t* public_key, const uint8_t* client_id, const uint8_t* sendback_data,  uint16_t length,
	 const uint8_t* shared_encryption_key)
 {
	 /* Check if packet is going to be sent to ourself. */
	 if (id_equal(public_key,m_selfPublicKey ))
		 return -1;

	 if (length != sizeof(uint64_t))
		 return -1;

	 size_t Node_format_size = sizeof(Node_format);
	 uint8_t *data=new uint8_t[1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + Node_format_size * MAX_SENT_NODES 
		 + length + crypto_box_MACBYTES];

	 Node_format nodes_list[MAX_SENT_NODES];
	 uint32_t num_nodes = get_close_nodes(client_id, nodes_list, 0, LAN_ip(ip_port.ip) == 0, 1);

	 uint8_t* plain=new uint8_t[1 + Node_format_size * MAX_SENT_NODES + length];
	 uint8_t encrypt[sizeof(plain) + crypto_box_MACBYTES];
	 uint8_t nonce[crypto_box_NONCEBYTES];
	 CryptoCore::newNonce(nonce);

	 int nodes_length = 0;

	 if (num_nodes) {
		 nodes_length = pack_nodes(plain + 1, Node_format_size * MAX_SENT_NODES, nodes_list, num_nodes);

		 if (nodes_length <= 0)
			 return -1;
	 }

	 plain[0] = num_nodes;
	 memcpy(plain + 1 + nodes_length, sendback_data, length);
	 int len = CryptoCore::decryptDataSymmetric(shared_encryption_key, nonce,	 plain, 1 + nodes_length + length, encrypt);

	 if (len != 1 + nodes_length + length + crypto_box_MACBYTES)
		 return -1;

	 data[0] = NET_PACKET_SEND_NODES_IPV6;
	 memcpy(data + 1, m_selfPublicKey, crypto_box_PUBLICKEYBYTES);
	 memcpy(data + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
	 memcpy(data + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, encrypt, len);

	 return   m_net->sendpacket( ip_port, data, 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + len);
 }


 int DHT::get_close_nodes(const uint8_t* public_key, Node_format* nodes_list, sa_family_t sa_family, uint8_t is_LAN, uint8_t want_good)
 {
	 memset(nodes_list, 0, MAX_SENT_NODES * sizeof(Node_format));
#ifdef ENABLE_ASSOC_DHT

	 if (!dht->assoc)
#endif
		 return get_somewhat_close_nodes(public_key, nodes_list, sa_family, is_LAN, want_good);

#ifdef ENABLE_ASSOC_DHT
	 //TODO: assoc, sa_family 0 (don't care if ipv4 or ipv6) support.
	 Client_data* result[MAX_SENT_NODES];

	 Assoc_close_entries request;
	 memset(&request, 0, sizeof(request));
	 request.count = MAX_SENT_NODES;
	 request.count_good = MAX_SENT_NODES - 2; /* allow 2 'indirect' nodes */
	 request.result = result;
	 request.wanted_id = public_key;
	 request.flags = (is_LAN ? LANOk : 0) + (sa_family == AF_INET ? ProtoIPv4 : ProtoIPv6);

	 uint8_t num_found = Assoc_get_close_entries(dht->assoc, &request);

	 if (!num_found) {
		 LOGGER_DEBUG("get_close_nodes(): Assoc_get_close_entries() returned zero nodes");
		 return get_somewhat_close_nodes(dht, public_key, nodes_list, sa_family, is_LAN, want_good);
	 }

	 LOGGER_DEBUG("get_close_nodes(): Assoc_get_close_entries() returned %i 'direct' and %i 'indirect' nodes",
		 request.count_good, num_found - request.count_good);

	 uint8_t i, num_returned = 0;

	 for (i = 0; i < num_found; i++) {
		 Client_data* client = result[i];

		 if (client) {
			 id_copy(nodes_list[num_returned].public_key, client->public_key);

			 if (sa_family == AF_INET)
				 if (ipport_isset(&client->assoc4.ip_port)) {
					 nodes_list[num_returned].ip_port = client->assoc4.ip_port;
					 num_returned++;
					 continue;
				 }

			 if (sa_family == AF_INET6)
				 if (ipport_isset(&client->assoc6.ip_port)) {
					 nodes_list[num_returned].ip_port = client->assoc6.ip_port;
					 num_returned++;
					 continue;
				 }
		 }
	 }

	 return num_returned;
#endif
 }


 /* Find MAX_SENT_NODES nodes closest to the public_key for the send nodes request:
 * put them in the nodes_list and return how many were found.
 *
 * TODO: For the love of based <your favorite deity, in doubt use "love"> make
 * this function cleaner and much more efficient.
 *
 * want_good : do we want only good nodes as checked with the hardening returned or not?
 */
 int DHT::get_somewhat_close_nodes(const uint8_t* public_key, Node_format* nodes_list, sa_family_t sa_family, uint8_t is_LAN, uint8_t want_good)
 {
	 uint32_t num_nodes = 0, i;
	 get_close_nodes_inner(public_key, nodes_list, sa_family, m_closeClientlist , LCLIENT_LIST, &num_nodes, is_LAN, 0);

	 /*TODO uncomment this when hardening is added to close friend clients
		 for (i = 0; i < dht->num_friends; ++i)
			 get_close_nodes_inner(dht, public_key, nodes_list, sa_family,
								   dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS,
								   &num_nodes, is_LAN, want_good);
	 */
	 for (i = 0; i <m_numFriends ; ++i)
		 get_close_nodes_inner(public_key, nodes_list, sa_family,m_friendsList[i].client_list, MAX_FRIEND_CLIENTS, &num_nodes, is_LAN, 0);
	 return num_nodes;
 }

 /* return 0 if no
   return 1 if yes */
 uint8_t  DHT::sent_getnode_to_node(const uint8_t* public_key, IP_Port node_ip_port, uint64_t ping_id, Node_format* sendback_node)
 {
	 uint8_t data[sizeof(Node_format) * 2];

	 if (ping_array_check(data, sizeof(data), &m_dhtPingArray , ping_id) == sizeof(Node_format)) 
	 {
		 memset(sendback_node, 0, sizeof(Node_format));
	 }
	 else if (ping_array_check(data, sizeof(data), &m_dhtHardenPingArray, ping_id) == sizeof(data))
	 {
		 memcpy(sendback_node, data + sizeof(Node_format), sizeof(Node_format));
	 }
	 else {
		 return 0;
	 }

	 Node_format test;
	 memcpy(&test, data, sizeof(Node_format));

	 if (!ipport_equal(&test.ip_port, &node_ip_port) || CryptoCore::publicKeyCmp (test.public_key, public_key) != 0)
		 return 0;
	 return 1;
 }


 /* Send a get node hardening response */
  int DHT::send_hardening_getnode_res(const Node_format* sendto, const uint8_t* queried_client_id,	 const uint8_t* nodes_data, uint16_t nodes_data_length)
 {
	 if (!ip_isset(&sendto->ip_port.ip))
		 return -1;

	 uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];
	 uint8_t *data =new uint8_t[nodes_data_length+crypto_box_PUBLICKEYBYTES  +1];
	 data[0] = CHECK_TYPE_GETNODE_RES;
	 memcpy(data + 1, queried_client_id, crypto_box_PUBLICKEYBYTES);
	 memcpy(data + 1 + crypto_box_PUBLICKEYBYTES, nodes_data, nodes_data_length);
	 int len =CryptoCore:: create_request(m_selfPublicKey ,  m_selfSecretKey, packet, sendto->public_key, data, sizeof(data), CRYPTO_PACKET_HARDENING);

	 if (len == -1)
	 {
		 delete[] data;
		 return -1;
	 }		 
	 delete[] data;
	 return  m_net->sendpacket(sendto->ip_port, packet, len);
 }


  /* Check if the node obtained with a get_nodes with public_key should be pinged.
   * NOTE: for best results call it after addto_lists;
   *
   * return 0 if the node should not be pinged.
   * return 1 if it should.
   */
  unsigned int DHT::ping_node_from_getnodes_ok(const uint8_t* public_key, IP_Port ip_port)
  {
	  bool ret = 0;

	  if ( add_to_close(public_key, ip_port, 1) == 0) {
		  ret = 1;
	  }

	  if (ret && !client_in_nodelist(  m_toBootstrap ,m_numToBootstrap, public_key)) {
		  if (m_numToBootstrap < MAX_CLOSE_TO_BOOTSTRAP_NODES) {
			  memcpy(m_toBootstrap[m_numToBootstrap].public_key, public_key, crypto_box_PUBLICKEYBYTES);
			  m_toBootstrap[m_numToBootstrap].ip_port = ip_port;
			  ++m_numToBootstrap;
		  }
		  else {
			  //TODO: ipv6 vs v4
			  add_to_list(m_toBootstrap, MAX_CLOSE_TO_BOOTSTRAP_NODES, public_key, ip_port,m_selfPublicKey);
		  }
	  }

	  unsigned int i;

	  for (i = 0; i <m_numFriends ; ++i) {
		  bool store_ok = 0;

		  DHT_Friend* friend1 = &m_friendsList[i];

		  if (store_node_ok(&friend1->client_list[1], public_key, friend1->public_key)) {
			  store_ok = 1;
		  }

		  if (store_node_ok(&friend1->client_list[0], public_key, friend1->public_key)) {
			  store_ok = 1;
		  }

		  if (store_ok && !client_in_nodelist(friend1->to_bootstrap, friend1->num_to_bootstrap, public_key)
			  && !is_pk_in_client_list(friend1->client_list, MAX_FRIEND_CLIENTS, public_key, ip_port)) {
			  if (friend1->num_to_bootstrap < MAX_SENT_NODES) {
				  memcpy(friend1->to_bootstrap[friend1->num_to_bootstrap].public_key, public_key, crypto_box_PUBLICKEYBYTES);
				  friend1->to_bootstrap[friend1->num_to_bootstrap].ip_port = ip_port;
				  ++friend1->num_to_bootstrap;
			  }
			  else {
				  add_to_list(friend1->to_bootstrap, MAX_SENT_NODES, public_key, ip_port, friend1->public_key);
			  }

			  ret = 1;
		  }
	  }

	  return ret;
  }

  /* Add node to close list.
 *
 * simulate is set to 1 if we want to check if a node can be added to the list without adding it.
 *
 * return -1 on failure.
 * return 0 on success.
 */
   int DHT::add_to_close( const uint8_t* public_key, IP_Port ip_port, bool simulate)
  {
	  unsigned int i;

	  unsigned int index = bit_by_bit_cmp(public_key, m_selfPublicKey);

	  if (index > LCLIENT_LENGTH)
		  index = LCLIENT_LENGTH - 1;

	  for (i = 0; i < LCLIENT_NODES; ++i) {
		  Client_data* client = &m_closeClientlist[(index * LCLIENT_NODES) + i];

		  if (is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT) && is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT)) {
			  if (!simulate) {
				  IPPTsPng* ipptp_write = NULL;
				  IPPTsPng* ipptp_clear = NULL;

				  if (ip_port.ip.family == AF_INET) {
					  ipptp_write = &client->assoc4;
					  ipptp_clear = &client->assoc6;
				  }
				  else {
					  ipptp_write = &client->assoc6;
					  ipptp_clear = &client->assoc4;
				  }

				  id_copy(client->public_key, public_key);
				  ipptp_write->ip_port = ip_port;
				  ipptp_write->timestamp = unix_time();

				  ip_reset(&ipptp_write->ret_ip_port.ip);
				  ipptp_write->ret_ip_port.port = 0;
				  ipptp_write->ret_timestamp = 0;

				  /* zero out other address */
				  memset(ipptp_clear, 0, sizeof(*ipptp_clear));
			  }

			  return 0;
		  }
	  }

	  return -1;
  }



   /* If public_key is a friend or us, update ret_ip_port
	* nodepublic_key is the id of the node that sent us this info.
	*/
   int DHT::returnedip_ports( IP_Port ip_port, const uint8_t* public_key, const uint8_t* nodepublic_key)
   {
	   uint32_t i, j;
	   uint64_t temp_time = unix_time();

	   uint32_t used = 0;

	   /* convert IPv4-in-IPv6 to IPv4 */
	   if ((ip_port.ip.family == AF_INET6) && IPV6_IPV4_IN_V6(ip_port.ip.ip6)) {
		   ip_port.ip.family = AF_INET;
		   ip_port.ip.ip4.uint32 = ip_port.ip.ip6.uint32[3];
	   }

	   if (id_equal(public_key, m_selfPublicKey)) {
		   for (i = 0; i < LCLIENT_LIST; ++i) {
			   if (id_equal(nodepublic_key, m_closeClientlist[i].public_key)) {
				   if (ip_port.ip.family == AF_INET) {
					   m_closeClientlist[i].assoc4.ret_ip_port = ip_port;
					   m_closeClientlist[i].assoc4.ret_timestamp = temp_time;
				   }
				   else if (ip_port.ip.family == AF_INET6) {
					   m_closeClientlist[i].assoc6.ret_ip_port = ip_port;
					   m_closeClientlist[i].assoc6.ret_timestamp = temp_time;
				   }

				   ++used;
				   break;
			   }
		   }
	   }
	   else {
		   for (i = 0; i < m_numFriends; ++i) {
			   if (id_equal(public_key,m_friendsList[i].public_key)) {
				   for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
					   if (id_equal(nodepublic_key, m_friendsList[i].client_list[j].public_key)) {
						   if (ip_port.ip.family == AF_INET) {
							   m_friendsList[i].client_list[j].assoc4.ret_ip_port = ip_port;
							   m_friendsList[i].client_list[j].assoc4.ret_timestamp = temp_time;
						   }
						   else if (ip_port.ip.family == AF_INET6) {
							   m_friendsList[i].client_list[j].assoc6.ret_ip_port = ip_port;
							   m_friendsList[i].client_list[j].assoc6.ret_timestamp = temp_time;
						   }

						   ++used;
						   goto end;
					   }
				   }
			   }
		   }
	   }

   end:
#ifdef ENABLE_ASSOC_DHT

	   if (dht->assoc) {
		   IPPTs ippts;
		   ippts.ip_port = ip_port;
		   ippts.timestamp = temp_time;
		   /* this is only a hear-say entry, so ret-ipp is NULL, but used is required
			* to decide how valuable it is ("used" may throw an "unused" entry out) */
		   Assoc_add_entry(dht->assoc, public_key, &ippts, NULL, used ? 1 : 0);
	   }

#endif
	   return 0;
   }




   /* Send the given packet to node with public_key
	*使用public_key将给定数据包发送到节点
	*  return -1 if failure.*/
   int DHT::route_packet(const uint8_t* public_key, const uint8_t* packet, uint16_t length)
   {
	   uint32_t i;

	   for (i = 0; i < LCLIENT_LIST; ++i) {
		   if (id_equal(public_key, m_closeClientlist[i].public_key)) {
			   const Client_data* client = &m_closeClientlist[i];

			   if (ip_isset(&client->assoc6.ip_port.ip))
				   return  m_net->sendpacket(client->assoc6.ip_port, packet, length);
			   else if (ip_isset(&client->assoc4.ip_port.ip))
				   return m_net->sendpacket(client->assoc4.ip_port, packet, length);
			   else
				   break;
		   }
	   }
	   return -1;
   }


   /*  return friend number from the public_key.从public_key返回朋友号码。
 *  return -1 if a failure occurs. */
   int DHT::friend_number(const uint8_t* public_key)
   {
	   uint32_t i;

	   for (i = 0; i < m_numFriends; ++i) {
		   if (id_equal(m_friendsList[i].public_key, public_key))
			   return i;
	   }
	   return -1;
   }


   int DHT::send_NATping(const uint8_t* public_key, uint64_t ping_id, uint8_t type)
   {
	   uint8_t data[sizeof(uint64_t) + 1];
	   uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];

	   int num = 0;

	   data[0] = type;
	   memcpy(data + 1, &ping_id, sizeof(uint64_t));
	   /* 254 is NAT ping request packet id */
	   int len =CryptoCore::create_request (m_selfPublicKey, m_selfSecretKey, packet, public_key, data, sizeof(uint64_t) + 1, CRYPTO_PACKET_NAT_PING);

	   if (len == -1)
		   return -1;

	   if (type == 0) /* If packet is request use many people to route it. */
		   num = route_tofriend(public_key, packet, len);
	   else if (type == 1) /* If packet is response use only one person to route it */
		   num = routeone_tofriend(public_key, packet, len);

	   if (num == 0)
		   return -1;

	   return num;
   }



   /* Send the following packet to everyone who tells us they are connected to friend_id.
	*将以下数据包发送给告诉我们他们已连接到friend_id的所有人。
	*  return ip for friend.
	*  return number of nodes the packet was sent to. (Only works if more than (MAX_FRIEND_CLIENTS / 4).
	*/
   int DHT::route_tofriend(const uint8_t* friend_id, const uint8_t* packet, uint16_t length)
   {
	   int num = friend_number(friend_id);

	   if (num == -1)
		   return 0;

	   uint32_t i, sent = 0;
	   uint8_t friend_sent[MAX_FRIEND_CLIENTS] = { 0 };

	   IP_Port ip_list[MAX_FRIEND_CLIENTS];
	   int ip_num = friend_iplist(ip_list, num);

	   if (ip_num < (MAX_FRIEND_CLIENTS / 4))
		   return 0; /* Reason for that? */

	   DHT_Friend * friend1 = &m_friendsList[num];
	   Client_data * client;

	   /* extra legwork, because having the outside allocating the space for us
		* is *usually* good(tm) (bites us in the behind in this case though) */
	   uint32_t a;

	   for (a = 0; a < 2; a++)
		   for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
			   if (friend_sent[i])/* Send one packet per client.*/
				   continue;

			   client = &friend1->client_list[i];
			   IPPTsPng* assoc = NULL;

			   if (!a)
				   assoc = &client->assoc4;
			   else
				   assoc = &client->assoc6;

			   /* If ip is not zero and node is good. */
			   if (ip_isset(&assoc->ret_ip_port.ip) &&
				   !is_timeout(assoc->ret_timestamp, BAD_NODE_TIMEOUT)) {
				   int retval =m_net->sendpacket(assoc->ip_port, packet, length);

				   if ((unsigned int)retval == length) {
					   ++sent;
					   friend_sent[i] = 1;
				   }
			   }
		   }

	   return sent;
   }

   /* Puts all the different ips returned by the nodes for a friend_num into array ip_portlist.
 * ip_portlist must be at least MAX_FRIEND_CLIENTS big.
 *将friend_num的节点返回的所有不同ips放入array ip_portlist。 ip_portlist必须至少MAX_FRIEND_CLIENTS很大。
 *  return the number of ips returned.
 *  return 0 if we are connected to friend or if no ips were found.
 *  return -1 if no such friend.
 */
   int DHT::friend_iplist(IP_Port* ip_portlist, uint16_t friend_num)
   {
	   if (friend_num >=m_numFriends)
		   return -1;

	   DHT_Friend * friend1= &m_friendsList[friend_num];
	   Client_data * client;
	   IP_Port ipv4s[MAX_FRIEND_CLIENTS];
	   int num_ipv4s = 0;
	   IP_Port ipv6s[MAX_FRIEND_CLIENTS];
	   int num_ipv6s = 0;
	   int i;

	   for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
		   client = &(friend1->client_list[i]);

		   /* If ip is not zero and node is good. */
		   if (ip_isset(&client->assoc4.ret_ip_port.ip) && !is_timeout(client->assoc4.ret_timestamp, BAD_NODE_TIMEOUT)) {
			   ipv4s[num_ipv4s] = client->assoc4.ret_ip_port;
			   ++num_ipv4s;
		   }

		   if (ip_isset(&client->assoc6.ret_ip_port.ip) && !is_timeout(client->assoc6.ret_timestamp, BAD_NODE_TIMEOUT)) {
			   ipv6s[num_ipv6s] = client->assoc6.ret_ip_port;
			   ++num_ipv6s;
		   }

		   if (id_equal(client->public_key, friend1->public_key))
			   if (!is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT) || !is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT))
				   return 0; /* direct connectivity */
	   }

#ifdef FRIEND_IPLIST_PAD
	   memcpy(ip_portlist, ipv6s, num_ipv6s * sizeof(IP_Port));

	   if (num_ipv6s == MAX_FRIEND_CLIENTS)
		   return MAX_FRIEND_CLIENTS;

	   int num_ipv4s_used = MAX_FRIEND_CLIENTS - num_ipv6s;

	   if (num_ipv4s_used > num_ipv4s)
		   num_ipv4s_used = num_ipv4s;

	   memcpy(&ip_portlist[num_ipv6s], ipv4s, num_ipv4s_used * sizeof(IP_Port));
	   return num_ipv6s + num_ipv4s_used;

#else /* !FRIEND_IPLIST_PAD */

	   /* there must be some secret reason why we can't pad the longer list
		* with the shorter one...
		*/
	   if (num_ipv6s >= num_ipv4s) {
		   memcpy(ip_portlist, ipv6s, num_ipv6s * sizeof(IP_Port));
		   return num_ipv6s;
	   }

	   memcpy(ip_portlist, ipv4s, num_ipv4s * sizeof(IP_Port));
	   return num_ipv4s;

#endif /* !FRIEND_IPLIST_PAD */
   }

   /* Send the following packet to one random person who tells us they are connected to friend_id.
 *将以下数据包发送给一个告诉我们他们已连接到friend_id的随机人员。
 *  return number of nodes the packet was sent to.
 */
   int DHT::routeone_tofriend(const uint8_t* friend_id, const uint8_t* packet, uint16_t length)
   {
	   int num = friend_number(friend_id);

	   if (num == -1)
		   return 0;

	   DHT_Friend * friend1 = &m_friendsList[num];
	   Client_data * client;

	   IP_Port ip_list[MAX_FRIEND_CLIENTS * 2];
	   int n = 0;
	   uint32_t i;

	   /* extra legwork, because having the outside allocating the space for us
		* is *usually* good(tm) (bites us in the behind in this case though) */
	   uint32_t a;

	   for (a = 0; a < 2; a++)
		   for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
			   client = &friend1->client_list[i];
			   IPPTsPng* assoc = NULL;

			   if (!a)
				   assoc = &client->assoc4;
			   else
				   assoc = &client->assoc6;

			   /* If ip is not zero and node is good. */
			   if (ip_isset(&assoc->ret_ip_port.ip) && !is_timeout(assoc->ret_timestamp, BAD_NODE_TIMEOUT)) {
				   ip_list[n] = assoc->ip_port;
				   ++n;
			   }
		   }

	   if (n < 1)
		   return 0;

	   int retval = m_net->sendpacket(ip_list[rand() % n], packet, length);

	   if ((unsigned int)retval == length)
		   return 1;

	   return 0;
   }


   void DHT::cryptopacket_registerhandler(uint8_t byte, cryptopacket_handler_callback cb, void* object)
   {
	   m_cryptopackethandlers[byte].function = cb;
	   m_cryptopackethandlers[byte].object = object;
   }


   /* Send a getnodes request.发送getnodes请求。sendback_node是它将响应发送回的节点（设置为NULL以禁用此功能）
   sendback_node is the node that it will send back the response to (set to NULL to disable this) */
   int DHT::getnodes(IP_Port ip_port, const uint8_t* public_key, const uint8_t* client_id,   const Node_format* sendback_node)
   {
	   /* Check if packet is going to be sent to ourself. */
	   if (id_equal(public_key,m_selfPublicKey))
		   return -1;

	   uint8_t plain_message[sizeof(Node_format) * 2] = { 0 };

	   Node_format receiver;
	   memcpy(receiver.public_key, public_key, crypto_box_PUBLICKEYBYTES);
	   receiver.ip_port = ip_port;
	   memcpy(plain_message, &receiver, sizeof(receiver));

	   uint64_t ping_id = 0;

	   if (sendback_node != NULL) {
		   memcpy(plain_message + sizeof(receiver), sendback_node, sizeof(Node_format));
		   ping_id = ping_array_add(&m_dhtHardenPingArray, plain_message, sizeof(plain_message));
	   }
	   else {
		   ping_id = ping_array_add(&m_dhtPingArray, plain_message, sizeof(receiver));
	   }

	   if (ping_id == 0)
		   return -1;

	   uint8_t plain[crypto_box_PUBLICKEYBYTES + sizeof(ping_id)];
	   uint8_t encrypt[sizeof(plain) + crypto_box_MACBYTES];
	   uint8_t data[1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + sizeof(encrypt)];

	   memcpy(plain, client_id, crypto_box_PUBLICKEYBYTES);
	   memcpy(plain + crypto_box_PUBLICKEYBYTES, &ping_id, sizeof(ping_id));

	   uint8_t shared_key[crypto_box_BEFORENMBYTES];
	   getSharedKeySent(shared_key, public_key);

	   uint8_t nonce[crypto_box_NONCEBYTES];
	  CryptoCore::newNonce(nonce);

	   int len =  CryptoCore::encryptDataSymmetric(shared_key, nonce,  plain,  sizeof(plain),   encrypt);

	   if (len != sizeof(encrypt))
		   return -1;

	   data[0] = NET_PACKET_GET_NODES;
	   memcpy(data + 1, m_selfPublicKey, crypto_box_PUBLICKEYBYTES);
	   memcpy(data + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
	   memcpy(data + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, encrypt, len);

	   return  m_net->sendpacket( ip_port, data, sizeof(data));
   }


   /*
 * check how many nodes in nodes are also present in the closelist.检查关闭列表中是否还存在节点中的节点数。
 * TODO: make this function better.
 */
   uint32_t DHT::have_nodes_closelist(Node_format* nodes, uint16_t num)
   {
	   uint32_t counter = 0;
	   uint32_t i;

	   for (i = 0; i < num; ++i) {
		   if (id_equal(nodes[i].public_key,m_selfPublicKey )) {
			   ++counter;
			   continue;
		   }

		   IPPTsPng* temp = get_closelist_IPPTsPng(nodes[i].public_key, nodes[i].ip_port.ip.family);

		   if (temp) {
			   if (!is_timeout(temp->timestamp, BAD_NODE_TIMEOUT)) {
				   ++counter;
			   }
		   }
	   }

	   return counter;
   }


   /* TODO: improve */
   IPPTsPng* DHT::get_closelist_IPPTsPng(const uint8_t* public_key, sa_family_t sa_family)
   {
	   uint32_t i;

	   for (i = 0; i < LCLIENT_LIST; ++i) {
		   if (  CryptoCore::publicKeyCmp( m_closeClientlist[i].public_key, public_key) != 0)
			   continue;

		   if (sa_family == AF_INET)
			   return &m_closeClientlist[i].assoc4;
		   else if (sa_family == AF_INET6)
			   return &m_closeClientlist[i].assoc6;
	   }
	   return NULL;
   }



   /* Add a new friend to the friends list.	* public_key must be crypto_box_PUBLICKEYBYTES bytes long.
	* ip_callback is the callback of a function that will be called when the ip address	* is found along with arguments data and number.
	* lock_count will be set to a non zero number that must be passed to DHT_delfriend()	* to properly remove the callback.
	*将新朋友添加到朋友列表中。 public_key必须是crypto_box_PUBLICKEYBYTES个字节。 ip_callback是一个函数的回调，
	当找到ip地址以及参数data和number时	，将调用该函数。 lock_count将设置为非零数字，必须传递给DHT_delfriend（）才能正确删除回调。
	*  return 0 if success.
	*  return -1 if failure (friends list is full).
	*/
   int DHT::addfriend(const uint8_t* public_key, void (*ip_callback)(void* data, int32_t number, IP_Port), void* data, int32_t number, uint16_t* lock_count)
   {
	   int friend_num = friend_number(public_key);

	   uint16_t lock_num;

	   if (friend_num != -1) { /* Is friend already in DHT? */
		   DHT_Friend* friend1 = &m_friendsList[friend_num];

		   if (friend1->lock_count == DHT_FRIEND_MAX_LOCKS)
			   return -1;

		   lock_num = friend1->lock_count;
		   ++friend1->lock_count;
		   friend1->callbacks[lock_num].ip_callback = ip_callback;
		   friend1->callbacks[lock_num].data = data;
		   friend1->callbacks[lock_num].number = number;

		   if (lock_count)
			   * lock_count = lock_num + 1;

		   return 0;
	   }

	   DHT_Friend* temp;
	   temp = (DHT_Friend*)realloc(m_friendsList, sizeof(DHT_Friend) * (m_numFriends + 1));

	   if (temp == NULL)
		   return -1;

	   m_friendsList = temp;
	   DHT_Friend * friend1 = &m_friendsList[m_numFriends];
	   memset(friend1, 0, sizeof(DHT_Friend));
	   memcpy(friend1->public_key, public_key, crypto_box_PUBLICKEYBYTES);

	   friend1->nat.NATping_id = random_64b();
	   ++m_numFriends;

	   lock_num = friend1->lock_count;
	   ++friend1->lock_count;
	   friend1->callbacks[lock_num].ip_callback = ip_callback;
	   friend1->callbacks[lock_num].data = data;
	   friend1->callbacks[lock_num].number = number;

	   if (lock_count)
		   * lock_count = lock_num + 1;

	   friend1->num_to_bootstrap = get_close_nodes(friend1->public_key, friend1->to_bootstrap, 0, 1, 0);
	   return 0;
   }


   void DHT_bootstrap(DHT* dht, IP_Port ip_port, const uint8_t* public_key)
   {
	   /*#ifdef ENABLE_ASSOC_DHT
		  if (dht->assoc) {
			  IPPTs ippts;
			  ippts.ip_port = ip_port;
			  ippts.timestamp = 0;

			  Assoc_add_entry(dht->assoc, public_key, &ippts, NULL, 0);
		  }
		  #endif*/

	    dht->getnodes (ip_port, public_key, dht->selfPublicKey(), NULL);
   }




   /*  return 0 if we are not connected to the DHT.
	*  return 1 if we are.
	*/
   int DHT_isconnected(const DHT* dht)
   {
	   uint32_t i;
	   unix_time_update();
	   for (i = 0; i < LCLIENT_LIST; ++i) {
		   const Client_data* client = &dht->m_closeClientlist[i];

		   if (!is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT) ||
			   !is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT))
			   return 1;
	   }

	   return 0;
   }

   
/*  return 0 if we are not connected or only connected to lan peers with the DHT.
 *  return 1 if we are.
 */
int DHT_non_lan_connected(const DHT *dht)
{
    uint32_t i;
    unix_time_update();

    for (i = 0; i < LCLIENT_LIST; ++i) {
        const Client_data *client = &dht->m_closeClientlist[i];

        if (!is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT) && LAN_ip(client->assoc4.ip_port.ip) == -1)
            return 1;

        if (!is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT) && LAN_ip(client->assoc6.ip_port.ip) == -1)
            return 1;

    }

    return 0;
}

/* Put up to max_num nodes in nodes from the closelist.
 *
 * return the number of nodes.
 */
uint16_t list_nodes(Client_data* list, unsigned int length, Node_format* nodes, uint16_t max_num)
{
	if (max_num == 0)
		return 0;

	uint16_t count = 0;

	unsigned int i;

	for (i = length; i != 0; --i) {
		IPPTsPng* assoc = NULL;

		if (!is_timeout(list[i - 1].assoc4.timestamp, BAD_NODE_TIMEOUT))
			assoc = &list[i - 1].assoc4;

		if (!is_timeout(list[i - 1].assoc6.timestamp, BAD_NODE_TIMEOUT)) {
			if (assoc == NULL)
				assoc = &list[i - 1].assoc6;
			else if (rand() % 2)
				assoc = &list[i - 1].assoc6;
		}

		if (assoc != NULL) {
			memcpy(nodes[count].public_key, list[i - 1].public_key, crypto_box_PUBLICKEYBYTES);
			nodes[count].ip_port = assoc->ip_port;
			++count;

			if (count >= max_num)
				return count;
		}
	}

	return count;
}


/* Put up to max_num nodes in nodes from the closelist.
 *
 * return the number of nodes.
 */
uint16_t closelist_nodes(DHT* dht, Node_format* nodes, uint16_t max_num)
{
	return list_nodes(dht->m_closeClientlist , LCLIENT_LIST, nodes, max_num);
}

/* Put up to max_num nodes in nodes from the random friends.
 *
 * return the number of nodes.
 */
uint16_t randfriends_nodes(DHT* dht, Node_format* nodes, uint16_t max_num)
{
	if (max_num == 0)
		return 0;

	uint16_t count = 0;
	unsigned int i, r = rand();

	for (i = 0; i < DHT_FAKE_FRIEND_NUMBER; ++i) {
		count += list_nodes(dht->m_friendsList[(i + r) % DHT_FAKE_FRIEND_NUMBER].client_list, MAX_FRIEND_CLIENTS, nodes + count,
			max_num - count);

		if (count >= max_num)
			break;
	}

	return count;
}
