#pragma once

#include <QObject>

#include "libwgim_global.h"
#include "tcp_client.h"

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

private:
	Networking_Core  m_net{};
	Messenger_Options m_messengerOption {};
	unsigned int m_error = 0;
};
