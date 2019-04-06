#include "messenger.h"


Messenger::Messenger(Messenger_Options & options, unsigned int  error, QObject* parent)	: 
QObject(parent),m_error(error),m_messengerOption(options)
{
	m_messengerOption.ipv6enabled = true;
}

Messenger::Messenger( QObject* parent ) :	QObject(parent)
{
	m_messengerOption.ipv6enabled = true;
}
Messenger::~Messenger()
{
}

int Messenger::init()
{
	int ret = 0;

	//初始化socket并bind网络
	if (!m_messengerOption.udp_disabled)
	{
		IP ip{};
		ip.family = m_messengerOption.ipv6enabled ? AF_INET6 : AF_INET;		
		if (m_net->init(ip, m_messengerOption.port_range[0], m_messengerOption.port_range[1]))
		{
			m_error = Messenger::MESSENGER_ERROR_PORT;
			return Messenger::MESSENGER_ERROR_PORT;
		}			
	}
	//初始化m_dht,并添加两个fake朋友
	if (m_dht->init(m_net))
		return Messenger::MESSENGER_ERROR_DHT;

	if (m_net_crypto->init(m_dht, &m_messengerOption.proxy_info))
		return Messenger::MESSENGER_ERROR_TCP_SERVER;	


	onion = new_onion(m_dht.get());
	onion_a = new_onion_announce(m_dht.get());
	onion_c = new_onion_client(m_net_crypto);
	//fr_c = new_friend_connections(m_onion_c);
	return 0;
}
