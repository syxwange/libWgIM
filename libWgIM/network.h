#pragma once

#include <QObject>


#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>


#define MAX_UDP_PACKET_SIZE 2048

#define NET_PACKET_PING_REQUEST    0   /* Ping request packet ID. */
#define NET_PACKET_PING_RESPONSE   1   /* Ping response packet ID. */
#define NET_PACKET_GET_NODES       2   /* Get nodes request packet ID. */
#define NET_PACKET_SEND_NODES_IPV6 4   /* Send nodes response packet ID for other addresses. */
#define NET_PACKET_COOKIE_REQUEST  24  /* Cookie request packet */
#define NET_PACKET_COOKIE_RESPONSE 25  /* Cookie response packet */
#define NET_PACKET_CRYPTO_HS       26  /* Crypto handshake packet */
#define NET_PACKET_CRYPTO_DATA     27  /* Crypto data packet */
#define NET_PACKET_CRYPTO          32  /* Encrypted data packet ID. */
#define NET_PACKET_LAN_DISCOVERY   33  /* LAN discovery packet ID. */

/* See:  docs/Prevent_Tracking.txt and onion.{c, h} */
#define NET_PACKET_ONION_SEND_INITIAL 128
#define NET_PACKET_ONION_SEND_1 129
#define NET_PACKET_ONION_SEND_2 130

#define NET_PACKET_ANNOUNCE_REQUEST 131
#define NET_PACKET_ANNOUNCE_RESPONSE 132
#define NET_PACKET_ONION_DATA_REQUEST 133
#define NET_PACKET_ONION_DATA_RESPONSE 134

#define NET_PACKET_ONION_RECV_3 140
#define NET_PACKET_ONION_RECV_2 141
#define NET_PACKET_ONION_RECV_1 142

/* Only used for bootstrap nodes */
#define BOOTSTRAP_INFO_PACKET_ID 240


#define TOX_PORTRANGE_FROM 33445
#define TOX_PORTRANGE_TO   33545
#define TOX_PORT_DEFAULT   TOX_PORTRANGE_FROM

/* TCP related */
#define TCP_ONION_FAMILY (AF_INET6 + 1)
#define TCP_INET (AF_INET6 + 2)
#define TCP_INET6 (AF_INET6 + 3)
#define TCP_FAMILY (AF_INET6 + 4)


/* Does the IP6 struct a contain an IPv4 address in an IPv6 one? */
#define IPV6_IPV4_IN_V6(a) ((a.uint64[0] == 0) && (a.uint32[2] == htonl (0xffff)))

#define SIZE_IP4 4
#define SIZE_IP6 16
#define SIZE_IP (1 + SIZE_IP6)
#define SIZE_PORT 2
#define SIZE_IPPORT (SIZE_IP + SIZE_PORT)

#define TOX_ENABLE_IPV6_DEFAULT 1

/* addr_resolve return values */
#define TOX_ADDR_RESOLVE_INET  1
#define TOX_ADDR_RESOLVE_INET6 2


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
 * Packet data is put into data. * Packet length is put into length.
 *接收数据，ip和发送端口的函数放入ip_port。
 *分组数据被放入data。 *数据包长度len。 */
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
	int sendpacket(IP_Port ip_port, const uint8_t* data, uint16_t length);
	void networkingRegisterhandler(uint8_t byte, packet_handler_callback cb, void* object);

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
