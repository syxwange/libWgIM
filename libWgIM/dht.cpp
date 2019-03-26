#include "dht.h"



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
	//m_ping = new_ping(dht);

	return 0;
}
