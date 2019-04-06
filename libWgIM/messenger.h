#pragma once

#include <QObject>

#include "libwgim_global.h"
#include "tcp_client.h"

#include <memory>
#include "dht.h"
#include "net_crypto.h"
#include "onion.h"
#include "onion_announce.h"
#include "onion_client.h"

typedef struct {
	uint8_t ipv6enabled;
	uint8_t udp_disabled;
	TCP_Proxy_Info proxy_info;
	uint16_t port_range[2];
	uint16_t tcp_server_port;
} Messenger_Options;



class LIBWGIM_EXPORT Messenger : public QObject
{
	Q_OBJECT

public:
	Messenger(Messenger_Options & options, unsigned int error,QObject *parent=nullptr );
	Messenger(QObject* parent = nullptr);
	~Messenger();

	int init();

	enum  MESSENGER_ERROR {
		MESSENGER_ERROR_NONE,
		MESSENGER_ERROR_PORT,
		MESSENGER_ERROR_TCP_SERVER,
		MESSENGER_ERROR_DHT,
		MESSENGER_ERROR_OTHER
	};

private:
	std::shared_ptr<Networking_Core>   m_net{new Networking_Core};	
	Messenger_Options m_messengerOption {};
	std::shared_ptr<DHT> m_dht{new DHT};
	unsigned int m_error = 0;
	Net_Crypto* m_net_crypto{ new Net_Crypto };

	Onion* onion;
	Onion_Announce* onion_a;
	Onion_Client* onion_c;

	
};
