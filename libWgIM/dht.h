#pragma once

#include <QObject>
#include "cryptocore.h"
#include "utiliy.h"

/* Maximum number of clients stored per friend.ÿλ���Ѵ洢�����ͻ����� */
#define MAX_FRIEND_CLIENTS 8

#define LCLIENT_NODES (MAX_FRIEND_CLIENTS)
#define LCLIENT_LENGTH 128

/* A list of the clients mathematically closest to ours. ��ѧ����ӽ����ǵĿͻ��б�*/
#define LCLIENT_LIST (LCLIENT_LENGTH * LCLIENT_NODES)

#define MAX_CLOSE_TO_BOOTSTRAP_NODES 8

/* The max number of nodes to send with send nodes.�뷢�ͽڵ�һ���͵����ڵ����� */
#define MAX_SENT_NODES 4

/* Ping timeout in seconds  Ping��ʱ���룩*/
#define PING_TIMEOUT 5

/* size of DHT ping arrays. */
#define DHT_PING_ARRAY_SIZE 512

/* Ping interval in seconds for each node in our lists. �����б���ÿ���ڵ��Ping������룩��*/
#define PING_INTERVAL 60

/* The number of seconds for a non responsive node to become bad. ����Ӧ�ڵ�仵��������*/
#define PINGS_MISSED_NODE_GOES_BAD 1
#define PING_ROUNDTRIP 2
#define BAD_NODE_TIMEOUT (PING_INTERVAL + PINGS_MISSED_NODE_GOES_BAD * (PING_INTERVAL + PING_ROUNDTRIP))

/* Redefinitions of variables for safe transfer over wire. ���¶�������Ա㰲ȫ���䡣*/
#define TOX_AF_INET 2
#define TOX_AF_INET6 10
#define TOX_TCP_INET 130
#define TOX_TCP_INET6 138

/* The number of "fake" friends to add (for optimization purposes and so our paths for the onion part are more random)
*  Ҫ��ӵġ��١����ѵ�������Ϊ���Ż�Ŀ�ģ��������ǵ���в��ֵ�·���������*/
#define DHT_FAKE_FRIEND_NUMBER 2



typedef struct {
	/* Node routes request correctly  �ڵ�·��������ȷ (true (1) or false/didn't check (0)) */
	uint8_t     routes_requests_ok;
	/* Time which we last checked this.�����ϴμ���ʱ��*/
	uint64_t    routes_requests_timestamp;
	uint8_t     routes_requests_pingedid[crypto_box_PUBLICKEYBYTES];
	/* Node sends correct send_node �ڵ㷢����ȷ��send_node(true (1) or false/didn't check (0)) */
	uint8_t     send_nodes_ok;
	/* Time which we last checked this.*/
	uint64_t    send_nodes_timestamp;
	uint8_t     send_nodes_pingedid[crypto_box_PUBLICKEYBYTES];
	/* Node can be used to test other nodes �ڵ�����ڲ��������ڵ�(true (1) or false/didn't check (0)) */
	uint8_t     testing_requests;
	/* Time which we last checked this.*/
	uint64_t    testing_timestamp;
	uint8_t     testing_pingedid[crypto_box_PUBLICKEYBYTES];
} Hardening;

typedef struct {
	IP_Port     ip_port;
	uint64_t    timestamp;
	uint64_t    last_pinged;

	Hardening hardening;
	/* Returned by this node. Either our friend or us. �ɴ˽ڵ㷵�ء� ���������ǵ����ѻ�������*/
	IP_Port     ret_ip_port;
	uint64_t    ret_timestamp;
} IPPTsPng;

typedef struct {
	uint8_t     public_key[crypto_box_PUBLICKEYBYTES];
	IPPTsPng    assoc4;
	IPPTsPng    assoc6;
} Client_data;


typedef struct {
	/* 1 if currently hole punching, otherwise 0 �����ǰ���1������Ϊ0*/
	uint8_t     hole_punching;
	uint32_t    punching_index;
	uint32_t    tries;
	uint32_t    punching_index2;
	uint64_t    punching_timestamp;
	uint64_t    recvNATping_timestamp;
	uint64_t    NATping_id;
	uint64_t    NATping_timestamp;
} NAT;

#define DHT_FRIEND_MAX_LOCKS 32

typedef struct {
	uint8_t     public_key[crypto_box_PUBLICKEYBYTES];
	IP_Port     ip_port;
}Node_format;

typedef struct {
	uint8_t     public_key[crypto_box_PUBLICKEYBYTES];
	Client_data client_list[MAX_FRIEND_CLIENTS];
	/* Time at which the last get_nodes request was sent. �������һ��get_nodes�����ʱ�䡣 */
	uint64_t    lastgetnode;
	/* number of times get_node packets were sent. ����get_node���ݰ��Ĵ���*/
	uint32_t    bootstrap_times;
	/* Symetric NAT hole punching stuff. �Գ�NAT�ײ���*/
	NAT         nat;
	uint16_t lock_count;
	struct {
		void (*ip_callback)(void*, int32_t, IP_Port);
		void* data;
		int32_t number;
	} callbacks[DHT_FRIEND_MAX_LOCKS];
	Node_format to_bootstrap[MAX_SENT_NODES];
	unsigned int num_to_bootstrap;
} DHT_Friend;

#define MAX_KEYS_PER_SLOT 4
#define KEYS_TIMEOUT 600
typedef struct {
	struct {
		uint8_t public_key[crypto_box_PUBLICKEYBYTES];
		uint8_t shared_key[crypto_box_BEFORENMBYTES];
		uint32_t times_requested;
		uint8_t  stored; /* 0 if not, 1 if is */
		uint64_t time_last_requested;
	} keys[256 * MAX_KEYS_PER_SLOT];
} Shared_Keys;


typedef int (*cryptopacket_handler_callback)(void* object, IP_Port ip_port, const uint8_t* source_pubkey,	const uint8_t* data, uint16_t len);

typedef struct {
	cryptopacket_handler_callback function;
	void* object;
} Cryptopacket_Handles;


class Networking_Core;
class Ping;


class DHT : public QObject
{
	Q_OBJECT

public:
	DHT(QObject *parent=nullptr);
	~DHT();

	int init(std::shared_ptr<Networking_Core> net);
	uint8_t* selfPublicKey() { return m_selfPublicKey; }
	void getSharedKeySent(uint8_t* shared_key, const uint8_t* public_key);
	void getSharedKeyRecv(uint8_t* shared_key, const uint8_t* public_key);
	bool nodeAddableToCloseList(const uint8_t* public_key, IP_Port ip_port);
	int addToClose(const uint8_t* public_key, IP_Port ip_port, bool simulate);
	bool addToList(Node_format* nodes_list, unsigned int length, const uint8_t* pk, IP_Port ip_port, const uint8_t* cmp_pk);
	unsigned int bitByBitCmp(const uint8_t* pk1, const uint8_t* pk2);
	int getfriendip(const uint8_t* public_key, IP_Port* ip_port);

	std::shared_ptr<Networking_Core> getNetwork() { return m_net; }
	Ping* getPing() { return m_ping; }
	Client_data* getCloseClientList(){ return m_closeClientlist; }
private:
	void getSharedKey(Shared_Keys* shared_keys, uint8_t* shared_key, const uint8_t* secret_key, const uint8_t* public_key);

private:
	std::shared_ptr<Networking_Core> m_net=nullptr;
	Client_data    m_closeClientlist[LCLIENT_LIST]{};
	uint64_t       m_closeLastgetnodes=0;
	uint32_t       m_closeBootstrap_times=0;

	/* Note: this key should not be/is not used to transmit any sensitive materials����Կ��Ӧ����/�����ڴ����κ����в��� */
	uint8_t      m_secretSymmetric_key[crypto_box_KEYBYTES]{};
	/* DHT keypair ��Կ��*/
	uint8_t m_selfPublicKey[crypto_box_PUBLICKEYBYTES]{};
	uint8_t m_selfSecretKey[crypto_box_SECRETKEYBYTES]{};

	DHT_Friend* m_friendsList=nullptr;
	uint16_t       m_numFriends=0;

	Node_format* m_loadedNodesList=nullptr;
	uint32_t       m_loadedNumNodes=0;
	unsigned int   m_loadedNodesIndex=0;

	Shared_Keys m_sharedKeysRecv{};
	Shared_Keys m_sharedKeysSent{};

	Ping* m_ping=nullptr;
	Ping_Array    m_dhtPingArray{};
	Ping_Array    m_dhtHardenPingArray{};

	uint64_t       m_lastRun=0;

	Cryptopacket_Handles m_cryptopackethandlers[256]{};

	Node_format m_toBootstrap[MAX_CLOSE_TO_BOOTSTRAP_NODES]{};
	unsigned int m_numToBootstrap=0;
};
