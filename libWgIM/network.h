#pragma once

#include <QObject>


#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#define TOX_PORTRANGE_FROM 33445
#define TOX_PORTRANGE_TO   33545
#define TOX_PORT_DEFAULT   TOX_PORTRANGE_FROM

typedef unsigned int sock_t;
/* sa_family_t is the sockaddr_in / sockaddr_in6 family field */
typedef short sa_family_t;

typedef union {
	uint8_t uint8[4];
	uint16_t uint16[2];
	uint32_t uint32;
	struct in_addr in_addr;
}IP4;

typedef union {
	uint8_t uint8[16];
	uint16_t uint16[8];
	uint32_t uint32[4];
	uint64_t uint64[2];
	struct in6_addr in6_addr;
}IP6;


typedef struct {
	uint8_t family;
	union {
		IP4 ip4;
		IP6 ip6;
	};
}IP;

typedef struct {
	IP ip;
	uint16_t port;
}IP_Port;


/* Function to receive data, ip and port of sender is put into ip_port.
 * Packet data is put into data.
 * Packet length is put into length.
 */
typedef int (*packet_handler_callback)(void* object, IP_Port ip_port, const uint8_t* data, uint16_t len);

typedef struct {
	packet_handler_callback function;
	void* object;
} Packet_Handles;

class Networking_Core : public QObject
{
	Q_OBJECT

public:
	Networking_Core(QObject* parent=nullptr);
	int init(const IP & ip, uint16_t port_from, uint16_t port_to);
	~Networking_Core();

	//调用WSAStartup（）如调用所请求的Socket库，并初始化libsodium库 ，成功m_startupRan=1
	int networkStartup();
	//设置socket是IPv4 + IPv6双模式
	int setSocketDualstack(sock_t sock);
	static uint64_t currentTimeActual(void);

private:

	Packet_Handles m_packethandlers[256]{};
	sa_family_t m_family=0;
	uint16_t m_port=0;
	/* Our UDP socket. */
	sock_t m_sock=0;
	unsigned int  m_error = 0;

	//调用WSAStartup（）如调用所请求的Socket库，并初始化libsodium库 ，成功m_startupRan=1
	uint8_t m_startupRan = 0;
} ;




class NetWork : public QObject
{
	Q_OBJECT

public:
	NetWork(QObject *parent);
	~NetWork();
};
