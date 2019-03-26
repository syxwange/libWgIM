#pragma once

#include <QObject>


#include "network.h"



typedef struct {
	IP_Port ip_port;
	uint8_t proxy_type; // a value from TCP_PROXY_TYPE
} TCP_Proxy_Info;

class TCP_client : public QObject
{
	Q_OBJECT

public:
	TCP_client(QObject *parent);
	~TCP_client();
};
