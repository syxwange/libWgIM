#include "dht.h"
#include "ping.h"


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

