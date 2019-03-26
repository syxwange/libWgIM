#include <QtCore/QCoreApplication>
#include "../libWgIM/libwgim.h"
#include <iostream>
#include "sodium.h"
#pragma comment(lib,"../x64/debug/libWgIM.lib")

#pragma comment(lib,"libsodium.lib")

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);
	auto i = sodium_init();
	libWgIM m;
	std::cout << m.add(3, 5)<<i;
	return a.exec();
}
