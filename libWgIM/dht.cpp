#include "dht.h"
#include "ping.h"

/*TODO: change this to 7 when done*/
#define HARDENING_ALL_OK 2
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


/* Check if client with public_key is already in list of length length.
 * If it is then set its corresponding timestamp to current time.
 * If the id is already in the list with a different ip_port, update it.
 *  TODO: Maybe optimize this.
 *
 *  return True(1) or False(0)
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

	/* public_key not in list yet: see if we can find an identical ip_port, in
	 * that case we kill the old public_key by overwriting it with the new one
	 * TODO: maybe we SHOULDN'T do that if that public_key is in a friend_list
	 * and the one who is the actual friend's public_key/address set? */
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

/* Replace a first bad (or empty) node with this one
 *  or replace a possibly bad node (tests failed or not done yet)
 *  that is further than any other in the list
 *  from the comp_public_key
 *  or replace a good node that is further
 *  than any other in the list from the comp_public_key
 *  and further than public_key.
 *
 * Do not replace any node if the list has no bad or possibly bad nodes
 *  and all nodes in the list are closer to comp_public_key
 *  than public_key.
 *
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
 * and close_clientlist.
 *
 *  returns 1+ if the item is used in any list, 0 else
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


