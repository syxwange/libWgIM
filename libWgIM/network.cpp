#include "network.h"
#include "sodium.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib,"libsodium.lib")

#define loglogdata(__message__, __buffer__, __buflen__, __ip_port__, __res__)

NetWork::NetWork(QObject *parent)	: QObject(parent)
{
}

NetWork::~NetWork()
{
}


Networking_Core::Networking_Core(QObject* parent) : QObject(parent)
{
}

int Networking_Core::init(const IP& ip, uint16_t port_from, uint16_t port_to)
{
	if (port_from == 0 && port_to == 0)
	{
		port_from = TOX_PORTRANGE_FROM;
		port_to = TOX_PORTRANGE_TO;
	}
	else if (port_from == 0 && port_to != 0)
	{
		port_from = port_to;
	}
	else if (port_from != 0 && port_to == 0)
	{
		port_to = port_from;
	}
	else if (port_from > port_to)
	{
		uint16_t temp = port_from;
		port_from = port_to;
		port_to = temp;
	}

	m_error = 2;
	// check for invalid IPs 
	if (ip.family != AF_INET && ip.family != AF_INET6)
	{
		m_error = 3;
		return 1;
	}

	if (networkStartup())
		return 1;

	m_family = ip.family;
	m_port = 0;

	/* Initialize our socket. */
	/* add log message what we're creating */
	m_sock = socket(m_family, SOCK_DGRAM, IPPROTO_UDP);

	/* Check for socket error. */
	if (m_sock == INVALID_SOCKET)
	{		
		m_error = 1;
		return 3;
	}

	/* Functions to increase the size of the send and receive UDP buffers.*/	
	int n = 1024 * 1024 * 2;
	setsockopt(m_sock, SOL_SOCKET, SO_RCVBUF, (char*)& n, sizeof(n));
	setsockopt(m_sock, SOL_SOCKET, SO_SNDBUF, (char*)& n, sizeof(n));

	/* Enable broadcast on socket */
	int broadcast = 1;
	setsockopt(m_sock, SOL_SOCKET, SO_BROADCAST, (char*)& broadcast, sizeof(broadcast));

	/* Set socket nonblocking. */
	u_long mode = 1;
	if (ioctlsocket(m_sock, FIONBIO, &mode))
	{
		m_error = 1;
		return 3;
	}


	/* Bind our socket to port PORT and the given IP address (usually 0.0.0.0 or ::) */
	uint16_t* portptr = nullptr;
	struct sockaddr_storage addr;
	size_t addrsize;

	if (m_family == AF_INET)
	{
		struct sockaddr_in* addr4 = (struct sockaddr_in*) & addr;
		addrsize = sizeof(struct sockaddr_in);
		addr4->sin_family = AF_INET;
		addr4->sin_port = 0;
		addr4->sin_addr = ip.ip4.in_addr;
		portptr = &addr4->sin_port;
	}
	if (m_family == AF_INET6)
	{
		struct sockaddr_in6* addr6 = (struct sockaddr_in6*) & addr;

		addrsize = sizeof(struct sockaddr_in6);
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = 0;
		addr6->sin6_addr = ip.ip6.in6_addr;

		addr6->sin6_flowinfo = 0;
		addr6->sin6_scope_id = 0;
		portptr = &addr6->sin6_port;
	}

	if (ip.family == AF_INET6)
	{
		setSocketDualstack(m_sock);
		/* multicast local nodes */
		struct ipv6_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		mreq.ipv6mr_multiaddr.s6_addr[0] = 0xFF;
		mreq.ipv6mr_multiaddr.s6_addr[1] = 0x02;
		mreq.ipv6mr_multiaddr.s6_addr[15] = 0x01;
		mreq.ipv6mr_interface = 0;
		setsockopt(m_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char*)& mreq, sizeof(mreq));		
	}

	uint16_t port_to_try = port_from;
	*portptr = htons(port_to_try);
	int tries;

	for (tries = port_from; tries <= port_to; tries++)
	{
		int res = bind(m_sock, (struct sockaddr*) & addr, addrsize);

		if (!res)
		{
			m_port = *portptr;
			/* errno isn't reset on success, only set on failure, the failed
			 * binds with parallel clients yield a -EPERM to the outside if
			 * errno isn't cleared here */
			if (tries > 0)
				errno = 0;
			m_error = 0;
			return 0;
		}

		port_to_try++;
		if (port_to_try > port_to)
			port_to_try = port_from;
		*portptr = htons(port_to_try);
	}
	return 1;
}

Networking_Core::~Networking_Core()
{
}

//调用WSAStartup（）如调用所请求的Socket库，并初始化libsodium库 ，成功m_startupRan=1
int Networking_Core::networkStartup()
{
	if (m_startupRan != 0)
		return 0;
	//libsodium没有添加
	sodium_init();

	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
		return -1;

	srand((uint32_t)currentTimeActual());
	m_startupRan = 1;
	return 0;	
}

uint64_t Networking_Core::currentTimeActual(void)
{
	uint64_t time;
	/* This probably works fine */
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	time = ft.dwHighDateTime;
	time <<= 32;
	time |= ft.dwLowDateTime;
	time -= 116444736000000000ULL;
	return time / 10;
}


/* Set socket to dual (IPv4 + IPv6 socket)
 *设置socket是IPv4 + IPv6双模式
 * return 1 on success
 * return 0 on failure
 */
int Networking_Core::setSocketDualstack(sock_t sock)
{
	int ipv6only = 0;
	socklen_t optsize = sizeof(ipv6only);
	int res = getsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)& ipv6only, &optsize);

	if ((res == 0) && (ipv6only == 0))
		return 1;

	ipv6only = 0;
	return (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)& ipv6only, sizeof(ipv6only)) == 0);
}


/* Basic network functions: Function to send packet(data) of length length to ip_port.
 *基本网络功能：将长度为length的数据包（数据）发送到ip_port的功能。*/
int Networking_Core::sendpacket(IP_Port ip_port, const uint8_t* data, uint16_t length)
{
	if (m_family == 0) /* Socket not initialized */
		return -1;

	/* socket AF_INET, but target IP NOT: can't send */
	if ((m_family == AF_INET) && (ip_port.ip.family != AF_INET))
		return -1;

	struct sockaddr_storage addr;
	size_t addrsize = 0;

	if (ip_port.ip.family == AF_INET)
	{
		if (m_family == AF_INET6) 
		{
			/* must convert to IPV4-in-IPV6 address */
			struct sockaddr_in6* addr6 = (struct sockaddr_in6*) & addr;

			addrsize = sizeof(struct sockaddr_in6);
			addr6->sin6_family = AF_INET6;
			addr6->sin6_port = ip_port.port;

			/* there should be a macro for this in a standards compliant
			 * environment, not found */
			IP6 ip6;

			ip6.uint32[0] = 0;
			ip6.uint32[1] = 0;
			ip6.uint32[2] = htonl(0xFFFF);
			ip6.uint32[3] = ip_port.ip.ip4.uint32;
			addr6->sin6_addr = ip6.in6_addr;

			addr6->sin6_flowinfo = 0;
			addr6->sin6_scope_id = 0;
		}
		else {
			struct sockaddr_in* addr4 = (struct sockaddr_in*) & addr;

			addrsize = sizeof(struct sockaddr_in);
			addr4->sin_family = AF_INET;
			addr4->sin_addr = ip_port.ip.ip4.in_addr;
			addr4->sin_port = ip_port.port;
		}
	}
	else if (ip_port.ip.family == AF_INET6) {
		struct sockaddr_in6* addr6 = (struct sockaddr_in6*) & addr;

		addrsize = sizeof(struct sockaddr_in6);
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = ip_port.port;
		addr6->sin6_addr = ip_port.ip.ip6.in6_addr;

		addr6->sin6_flowinfo = 0;
		addr6->sin6_scope_id = 0;
	}
	else {
		/* unknown address type*/
		return -1;
	}
	int res = sendto(m_sock, (char*)data, length, 0, (struct sockaddr*) & addr, addrsize);
	loglogdata("O=>", data, length, ip_port, res);
	return res;
}

void Networking_Core::networkingRegisterhandler(uint8_t byte, packet_handler_callback cb, void* object)
{	

	m_packethandlers[byte].function = cb;
	m_packethandlers[byte].object = object;
}