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
	auto i = sodium_init();
	Messenger m;
	auto ret = m.init();
	Utiliy::unixTimeUpdate();	
	std::cout <<"unixBaseTimeValue:"<< Utiliy::unixBaseTimeValue<<"lastMonotime:"<<Utiliy::lastMonotime<< "unixTimeValue:" << Utiliy::unixTimeValue<< "     "<<Utiliy::currentTimeMonotonic()<<std::endl;
	Utiliy::unixTimeUpdate();
	std::cout << "unixBaseTimeValue:" << Utiliy::unixBaseTimeValue << "lastMonotime:" << Utiliy::lastMonotime << "unixTimeValue:" << Utiliy::unixTimeValue << "     " << Utiliy::currentTimeMonotonic() << std::endl;
	Utiliy::unixTimeUpdate();
	std::cout << "unixBaseTimeValue:" << Utiliy::unixBaseTimeValue << "lastMonotime:" << Utiliy::lastMonotime << "unixTimeValue:" << Utiliy::unixTimeValue << "     " << Utiliy::currentTimeMonotonic() << std::endl;
	Utiliy::unixTimeUpdate();
	std::cout << "unixBaseTimeValue:" << Utiliy::unixBaseTimeValue << "lastMonotime:" << Utiliy::lastMonotime << "unixTimeValue:" << Utiliy::unixTimeValue << "     " << Utiliy::currentTimeMonotonic() << std::endl;

	Sleep(3000);
	Utiliy::unixTimeUpdate();
	std::cout << "unixBaseTimeValue:" << Utiliy::unixBaseTimeValue << "lastMonotime:" << Utiliy::lastMonotime << "unixTimeValue:" << Utiliy::unixTimeValue << "     " << Utiliy::currentTimeMonotonic() << std::endl;

	Sleep(30000);
	Utiliy::unixTimeUpdate();
	std::cout << "unixBaseTimeValue:" << Utiliy::unixBaseTimeValue << "lastMonotime:" << Utiliy::lastMonotime << "unixTimeValue:" << Utiliy::unixTimeValue << "     " << Utiliy::currentTimeMonotonic() << std::endl;

	return a.exec();
}
