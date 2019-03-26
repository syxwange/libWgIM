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
	if (!m_messengerOption.udp_disabled)
	{
		IP ip{};
		ip.family = m_messengerOption.ipv6enabled ? AF_INET6 : AF_INET;		
		m_net.init(ip, m_messengerOption.port_range[0], m_messengerOption.port_range[1]);
	}
	
	return 0;
}
