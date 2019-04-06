#include <QtCore/QCoreApplication>
#include "../libWgIM/libwgim.h"
#include <iostream>
#include "sodium.h"


#pragma comment(lib,"../x64/debug/libWgIM.lib")

#pragma comment(lib,"libsodium.lib")
#include "../libWgIM/messenger.h"

#include "../libWgIM/utiliy.h"

#define PORT 33445

void ip_init(IP* ip, uint8_t ipv6enabled)
{
	if (!ip)
		return;

	memset(ip, 0, sizeof(IP));
	ip->family = ipv6enabled ? AF_INET6 : AF_INET;
}

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);	
	

	Messenger_Options options = { 0 };
	options.ipv6enabled = 1;
	Messenger m;
	m.init();	
	
	return a.exec();
}
