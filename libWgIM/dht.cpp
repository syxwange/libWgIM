#include "dht.h"
#include "ping.h"


DHT::DHT(QObject *parent)	: QObject(parent)
{
	Utiliy::unixTimeUpdate();
}

DHT::~DHT()
{
}

int DHT::init(std::shared_ptr<Networking_Core> net)
{
	m_net = net;
	m_ping = new Ping;
	m_ping->init( static_cast<std::shared_ptr<DHT>>( this));

	return 0;
}


/* Shared key generations are costly, it is therefor smart to store commonly used
 * ones so that they can re used later without being computed again.
 *共享密钥生成是昂贵的，因此存储常用的密钥使得它们可以在以后重新使用而不再被计算。
 * If shared key is already in shared_keys, copy it to shared_key.
 * else generate it into shared_key and copy it to shared_keys
 *如果共享密钥已在shared_keys中，请将其复制到shared_key。 否则将其生成为shared_key并将其复制到shared_keys*/
void DHT::getSharedKey(Shared_Keys* shared_keys, uint8_t* shared_key, const uint8_t* secret_key, const uint8_t* public_key)
{
	uint32_t i, num = ~0, curr = 0;

	for (i = 0; i < MAX_KEYS_PER_SLOT; ++i)
	{
		int index = public_key[30] * MAX_KEYS_PER_SLOT + i;

		if (shared_keys->keys[index].stored) 
		{
			if ( CryptoCore::publicKeyCmp(public_key, shared_keys->keys[index].public_key) == 0)
			{
				memcpy(shared_key, shared_keys->keys[index].shared_key, crypto_box_BEFORENMBYTES);
				++shared_keys->keys[index].times_requested;
				shared_keys->keys[index].time_last_requested = unix_time();
				return;
			}

			if (num != 0) 
			{
				if (is_timeout(shared_keys->keys[index].time_last_requested, KEYS_TIMEOUT)) 
				{
					num = 0;
					curr = index;
				}
				else if (num > shared_keys->keys[index].times_requested) 
				{
					num = shared_keys->keys[index].times_requested;
					curr = index;
				}
			}
		}
		else 
		{
			if (num != 0)
			{
				num = 0;
				curr = index;
			}
		}
	}

	CryptoCore::encryptPrecompute(public_key, secret_key, shared_key);

	if (num != (uint32_t)~0) {
		shared_keys->keys[curr].stored = 1;
		shared_keys->keys[curr].times_requested = 1;
		memcpy(shared_keys->keys[curr].public_key, public_key, crypto_box_PUBLICKEYBYTES);
		memcpy(shared_keys->keys[curr].shared_key, shared_key, crypto_box_BEFORENMBYTES);
		shared_keys->keys[curr].time_last_requested = unix_time();
	}
}


/* Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_keyfor packets that we send
 * .复制shared_key以将来自public_key的DHT数据包加密/解密为我们发送的数据包的shared_key。
 */
void DHT::getSharedKeySent(uint8_t* shared_key, const uint8_t* public_key)
{
	getSharedKey(&m_sharedKeysSent, shared_key, m_selfSecretKey, public_key);
}
