#include "ping.h"
#include "utiliy.h"


Ping::Ping()
{
}


Ping::~Ping()
{
}

int Ping::init(std::shared_ptr<DHT> dht)
{
	m_dht = dht;
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
//
//
//	rc = encrypt_data_symmetric(shared_key,
//		pk + 1 + crypto_box_PUBLICKEYBYTES,
//		ping_plain, sizeof(ping_plain),
//		pk + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);
//
//	if (rc != PING_PLAIN_SIZE + crypto_box_MACBYTES)
//		return 1;
//
//	return sendpacket(ping->dht->net, ipp, pk, sizeof(pk));
//
}

