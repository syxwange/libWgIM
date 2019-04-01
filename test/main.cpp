#include <QtCore/QCoreApplication>
#include "../libWgIM/libwgim.h"
#include <iostream>
#include "sodium.h"
#pragma comment(lib,"../x64/debug/libWgIM.lib")

#pragma comment(lib,"libsodium.lib")
#include "../libWgIM/messenger.h"

#include "../libWgIM/utiliy.h"
int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);	
	//Messenger m;
	//m.init();
	uint32_t i, num = ~0, curr = 0;
	if (num >time(nullptr))
	{
		num = 0;
	}
	return a.exec();
}
