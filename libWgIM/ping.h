#pragma once

#include "utiliy.h"
#include "dht.h"

#define PING_NUM_MAX 512

/* Maximum newly announced nodes to ping per TIME_TO_PING seconds. 每TIME_TO_PING秒ping最多新发布的节点数。*/
#define MAX_TO_PING 32

/* Ping newly announced nodes to ping per TIME_TO_PING seconds  Ping新发布的节点按TIME_TO_PING秒进行ping操作*/
#define TIME_TO_PING 2

#define PING_PLAIN_SIZE (1 + sizeof(uint64_t))
#define DHT_PING_SIZE (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + PING_PLAIN_SIZE + crypto_box_MACBYTES)
#define PING_DATA_SIZE (crypto_box_PUBLICKEYBYTES + sizeof(IP_Port))

class DHT;

class Ping
{
public:
	Ping();
	~Ping();
	int init(std::shared_ptr<DHT> dht);
	int sendPingRequest(IP_Port ipp, const uint8_t* public_key);
	int sendPingResponse(IP_Port ipp, const uint8_t* public_key, uint64_t ping_id, uint8_t* shared_encryption_key);
	int inList(const Client_data* list, uint16_t length, const uint8_t* public_key, IP_Port ip_port);
	int addToPing(const uint8_t* public_key, IP_Port ip_port);

	std::shared_ptr<DHT> getDHT() { return m_dht; }
	Ping_Array getpingArray() { return m_pingArray; }

private:
	std::shared_ptr<DHT> m_dht = nullptr;

	Ping_Array m_pingArray{};
	Node_format m_toPing[MAX_TO_PING]{};
	uint64_t    m_lastToPing=0;
};

