#include "ping.h"
#include "utiliy.h"


static int handle_ping_request(void* _dht, IP_Port source, const uint8_t* packet, uint16_t length)
{
	DHT* dht =(DHT *) _dht;
	int        rc;

	if (length != DHT_PING_SIZE)
		return 1;

	Ping * ping = dht->getPing();

	if (id_equal(packet + 1, ping->getDHT()->selfPublicKey()))
		return 1;

	uint8_t shared_key[crypto_box_BEFORENMBYTES];

	uint8_t ping_plain[PING_PLAIN_SIZE];
	// Decrypt ping_id
	ping->getDHT()->getSharedKeyRecv(shared_key, packet + 1);
	rc = CryptoCore::decryptDataSymmetric(shared_key,	packet + 1 + crypto_box_PUBLICKEYBYTES,
		packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,		PING_PLAIN_SIZE + crypto_box_MACBYTES,	ping_plain);

	if (rc != sizeof(ping_plain))
		return 1;

	if (ping_plain[0] != NET_PACKET_PING_REQUEST)
		return 1;

	uint64_t   ping_id;
	memcpy(&ping_id, ping_plain + 1, sizeof(ping_id));
	// Send response
	ping->sendPingResponse(source, packet + 1, ping_id, shared_key);
	ping->addToPing(packet + 1, source);

	return 0;
}

static int handle_ping_response(void* _dht, IP_Port source, const uint8_t * packet, uint16_t length)
{
	DHT* dht =(DHT*) _dht;
	int       rc;

	if (length != DHT_PING_SIZE)
		return 1;

	Ping * ping = dht->getPing();

	if (id_equal(packet + 1, ping->getDHT()->selfPublicKey()))
		return 1;

	uint8_t shared_key[crypto_box_BEFORENMBYTES];

	// generate key to encrypt ping_id with recipient privkey
	ping->getDHT()->getSharedKeySent(shared_key, packet + 1);

	uint8_t ping_plain[PING_PLAIN_SIZE];
	// Decrypt ping_id
	rc = CryptoCore::decryptDataSymmetric(shared_key,		packet + 1 + crypto_box_PUBLICKEYBYTES,
		packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,	PING_PLAIN_SIZE + crypto_box_MACBYTES,	ping_plain);

	if (rc != sizeof(ping_plain))
		return 1;

	if (ping_plain[0] != NET_PACKET_PING_RESPONSE)
		return 1;

	uint64_t   ping_id;
	memcpy(&ping_id, ping_plain + 1, sizeof(ping_id));
	uint8_t data[PING_DATA_SIZE];

	if (ping_array_check(data, sizeof(data), &ping->getpingArray(), ping_id) != sizeof(data))
		return 1;

	if (!id_equal(packet + 1, data))
		return 1;

	IP_Port ipp;
	memcpy(&ipp, data + crypto_box_PUBLICKEYBYTES, sizeof(IP_Port));

	if (!ipport_equal(&ipp, &source))
		return 1;

	 (dht, source, packet + 1);
	return 0;
}



Ping::Ping()
{
}


Ping::~Ping()
{
}

int Ping::init(std::shared_ptr<DHT> dht)
{
	m_dht = dht;
	if (ping_array_init(&m_pingArray , PING_NUM_MAX, PING_TIMEOUT) != 0) 
	{		
		return  1;
	}	

	std::shared_ptr<int> shared_a(new int (10));
	auto  p = shared_a.get();	
	m_dht->getNetwork()->networkingRegisterhandler(NET_PACKET_PING_REQUEST, &handle_ping_request, dht.get());
	m_dht->getNetwork()->networkingRegisterhandler(NET_PACKET_PING_REQUEST, &handle_ping_response, dht.get());
	
	return 0;
}

int Ping::sendPingRequest(IP_Port ipp, const uint8_t* public_key)
{
	uint8_t   pk[DHT_PING_SIZE];
	int       rc;
	uint64_t  ping_id;

	if (id_equal(public_key, m_dht->selfPublicKey()))
		return 1;

	uint8_t shared_key[crypto_box_BEFORENMBYTES];

	// generate key to encrypt ping_id with recipient privkey以使用收件人privkey加密ping_id生成密钥	
	m_dht->getSharedKeySent(shared_key, public_key);
	// Generate random ping_id.
	uint8_t data[PING_DATA_SIZE];
	id_copy(data, public_key);
	memcpy(data + crypto_box_PUBLICKEYBYTES, &ipp, sizeof(IP_Port));
	ping_id = ping_array_add(&m_pingArray, data, sizeof(data));

	if (ping_id == 0)
		return 1;

	uint8_t ping_plain[PING_PLAIN_SIZE];
	ping_plain[0] = NET_PACKET_PING_REQUEST;
	memcpy(ping_plain + 1, &ping_id, sizeof(ping_id));

	pk[0] = NET_PACKET_PING_REQUEST;
	id_copy(pk + 1, m_dht->selfPublicKey());     // Our pubkey
	CryptoCore::newNonce(pk + 1 + crypto_box_PUBLICKEYBYTES); // Generate new nonce


	rc =  CryptoCore::encryptDataSymmetric(shared_key,pk + 1 + crypto_box_PUBLICKEYBYTES,
		ping_plain, sizeof(ping_plain),	pk + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);

	if (rc != PING_PLAIN_SIZE + crypto_box_MACBYTES)
		return 1;
	return m_dht->getNetwork()->sendpacket( ipp, pk, sizeof(pk));
}

int Ping::sendPingResponse(IP_Port ipp, const uint8_t* public_key, uint64_t ping_id,uint8_t* shared_encryption_key)
{
	uint8_t   pk[DHT_PING_SIZE];
	int       rc;

	if (id_equal(public_key,m_dht->selfPublicKey() ))
		return 1;

	uint8_t ping_plain[PING_PLAIN_SIZE];
	ping_plain[0] = NET_PACKET_PING_RESPONSE;
	memcpy(ping_plain + 1, &ping_id, sizeof(ping_id));

	pk[0] = NET_PACKET_PING_RESPONSE;
	id_copy(pk + 1, m_dht->selfPublicKey());     // Our pubkey
	CryptoCore::newNonce(pk + 1 + crypto_box_PUBLICKEYBYTES); // Generate new nonce

	// Encrypt ping_id using recipient privkey
	rc = CryptoCore::encryptDataSymmetric(shared_encryption_key,		pk + 1 + crypto_box_PUBLICKEYBYTES,
		ping_plain, sizeof(ping_plain),	pk + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);

	if (rc != PING_PLAIN_SIZE + crypto_box_MACBYTES)
		return 1;

	return m_dht->getNetwork()->sendpacket(ipp, pk, sizeof(pk));
}


/* Add nodes to the to_ping list.All nodes in this list are pinged every TIME_TO_PING seconds
 * and are then removed from the list. If the list is full the nodes farthest from our public_key are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the network while preventing amplification attacks.
 *将节点添加到to_ping列表。此列表中的所有节点每隔TIME_TO_PING秒被ping，然后从列表中删除。 如果列表已满，
 则替换最远离public_key的节点。 此列表的目的是使新节点快速集成到网络中，同时防止放大攻击。
 *  return 0 if node was added.   *  return -1 if node was not added. */
int Ping::addToPing(const uint8_t* public_key, IP_Port ip_port)
{
	if (!ip_isset(&ip_port.ip))
		return -1;

	if (! m_dht->nodeAddableToCloseList(public_key, ip_port))
		return -1;

	if (inList(m_dht->getCloseClientList(), LCLIENT_LIST, public_key, ip_port))
		return -1;

	IP_Port temp;

	if (m_dht->getfriendip(public_key, &temp) == 0) {
		sendPingRequest( ip_port, public_key);
		return -1;
	}
	unsigned int i;
	for (i = 0; i < MAX_TO_PING; ++i) {
		if (!ip_isset(&m_toPing[i].ip_port.ip)) 
		{
			memcpy(m_toPing[i].public_key, public_key, crypto_box_PUBLICKEYBYTES);			
			ipport_copy(&m_toPing[i].ip_port, &ip_port);
			return 0;
		}

		if ( CryptoCore::publicKeyCmp(m_toPing[i].public_key, public_key) == 0) {
			return -1;
		}
	}

	if (m_dht->addToList(m_toPing, MAX_TO_PING, public_key, ip_port, m_dht->selfPublicKey()))
		return 0;

	return -1;
}

/* Check if public_key with ip_port is in the list.
 *
 * return 1 if it is.
 * return 0 if it isn't.
 */
int Ping::inList(const Client_data* list, uint16_t length, const uint8_t* public_key, IP_Port ip_port)
{
	unsigned int i;

	for (i = 0; i < length; ++i) {
		if (id_equal(list[i].public_key, public_key)) {
			const IPPTsPng* ipptp;

			if (ip_port.ip.family == AF_INET) {
				ipptp = &list[i].assoc4;
			}
			else {
				ipptp = &list[i].assoc6;
			}

			if (!is_timeout(ipptp->timestamp, BAD_NODE_TIMEOUT) && ipport_equal(&ipptp->ip_port, &ip_port))
				return 1;
		}
	}

	return 0;
}

