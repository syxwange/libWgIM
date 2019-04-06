#include "cryptocore.h"


/* Precomputes the shared key from their public_key and our secret_key.
 * This way we can avoid an expensive elliptic curve scalar multiply for each
 * encrypt/decrypt operation.
 * enc_key has to be crypto_box_BEFORENMBYTES bytes long.
 */
void encrypt_precompute(const uint8_t* public_key, const uint8_t* secret_key, uint8_t* enc_key)
{
	crypto_box_beforenm(enc_key, public_key, secret_key);
}

int encrypt_data_symmetric(const uint8_t* secret_key, const uint8_t* nonce, const uint8_t* plain, uint32_t length,
	uint8_t* encrypted)
{
	if (length == 0 || !secret_key || !nonce || !plain || !encrypted)
		return -1;

	uint8_t *temp_plain =new uint8_t[length + crypto_box_ZEROBYTES];
	uint8_t *temp_encrypted= new uint8_t[length + crypto_box_MACBYTES + crypto_box_BOXZEROBYTES];

	memset(temp_plain, 0, crypto_box_ZEROBYTES);
	memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length); // Pad the message with 32 0 bytes.

	if (crypto_box_afternm(temp_encrypted, temp_plain, length + crypto_box_ZEROBYTES, nonce, secret_key) != 0)
	{
		delete[] temp_plain;
		delete[] temp_encrypted;
		return -1;
	}		

	/* Unpad the encrypted message. */
	memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, length + crypto_box_MACBYTES);
	delete[] temp_plain;
	delete[] temp_encrypted;
	return length + crypto_box_MACBYTES;
}


CryptoCore::CryptoCore(QObject *parent)	: QObject(parent)
{
}

CryptoCore::~CryptoCore()
{
}


/* compare 2 public keys of length crypto_box_PUBLICKEYBYTES, not vulnerable to timing attacks.
 *  returns 0 if both mem locations of length are equal,   return -1 if they are not.
 *  比较2个长度为crypto_box_PUBLICKEYBYTES的公钥，不易受时间攻击的影响。
 *  如果长度的两个mem位置相等，则返回0    如果不是，则返回-1。*/
int CryptoCore::publicKeyCmp(const uint8_t* pk1, const uint8_t* pk2)
{
	return crypto_verify_32(pk1, pk2);
}

/* Precomputes the shared key from their public_key and our secret_key.
 * This way we can avoid an expensive elliptic curve scalar multiply for each
 * encrypt/decrypt operation. * enc_key has to be crypto_box_BEFORENMBYTES bytes long.
 * 从他们的public_key和我们的secret_key预先计算共享密钥。 这样，
 * 我们可以避免每个加密/解密操作的昂贵的椭圆曲线标量乘法。 enc_key必须是crypto_box_BEFORENMBYTES个字节。
 */
void CryptoCore::encryptPrecompute(const uint8_t* public_key, const uint8_t* secret_key, uint8_t* enc_key)
{
	crypto_box_beforenm(enc_key, public_key, secret_key);
}


/* Fill the given nonce with random bytes.用随机字节填充给定的随机数 */
void CryptoCore::randomNonce(uint8_t* nonce)
{
	randombytes(nonce, crypto_box_NONCEBYTES);
}

/* Gives a nonce guaranteed to be different from previous ones.保证nonce与以前的nonce不同。*/
void CryptoCore::newNonce(uint8_t* nonce)
{
	randomNonce(nonce);
}

int CryptoCore::encryptDataSymmetric(const uint8_t* secret_key, const uint8_t* nonce, const uint8_t* plain,  uint32_t length,	uint8_t* encrypted)
{
	if (length == 0 || !secret_key || !nonce || !plain || !encrypted)
		return -1;

	uint8_t * temp_plain=new uint8_t[length + crypto_box_ZEROBYTES];
	uint8_t *temp_encrypted=new uint8_t[length + crypto_box_MACBYTES + crypto_box_BOXZEROBYTES];

	memset(temp_plain, 0, crypto_box_ZEROBYTES);
	memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length); // Pad the message with 32 0 bytes.

	if (crypto_box_afternm(temp_encrypted, temp_plain, length + crypto_box_ZEROBYTES, nonce, secret_key) != 0)
	{
		delete[] temp_plain;
		delete[] temp_encrypted;
		return -1;
	}
		

	/* Unpad the encrypted message. */
	memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, length + crypto_box_MACBYTES);

	delete[] temp_plain;
	delete[] temp_encrypted;
	return length + crypto_box_MACBYTES;
}

int CryptoCore::decryptDataSymmetric(const uint8_t* secret_key, const uint8_t* nonce, const uint8_t* encrypted, uint32_t length,	uint8_t* plain)
{
	if (length <= crypto_box_BOXZEROBYTES || !secret_key || !nonce || !encrypted || !plain)
		return -1;

	uint8_t *temp_plain=new uint8_t[length + crypto_box_ZEROBYTES];
	uint8_t *temp_encrypted = new uint8_t[length + crypto_box_BOXZEROBYTES];

	memset(temp_encrypted, 0, crypto_box_BOXZEROBYTES);
	memcpy(temp_encrypted + crypto_box_BOXZEROBYTES, encrypted, length); // Pad the message with 16 0 bytes.

	if (crypto_box_open_afternm(temp_plain, temp_encrypted, length + crypto_box_BOXZEROBYTES, nonce, secret_key) != 0)
		return -1;

	memcpy(plain, temp_plain + crypto_box_ZEROBYTES, length - crypto_box_MACBYTES);

	delete[] temp_plain;
	delete[] temp_encrypted;
	return length - crypto_box_MACBYTES;
}

int CryptoCore::create_request(const uint8_t* send_public_key, const uint8_t* send_secret_key, uint8_t* packet,
	const uint8_t* recv_public_key, const uint8_t* data, uint32_t length, uint8_t request_id)
{
	if (!send_public_key || !packet || !recv_public_key || !data)
		return -1;

	if (MAX_CRYPTO_REQUEST_SIZE < length + 1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + 1 +
		crypto_box_MACBYTES)
		return -1;

	uint8_t * nonce = packet + 1 + crypto_box_PUBLICKEYBYTES * 2;
	newNonce(nonce);
	uint8_t temp[MAX_CRYPTO_REQUEST_SIZE]; // FIXME sodium_memzero before exit function
	memcpy(temp + 1, data, length);
	temp[0] = request_id;
	int len = encrypt_data(recv_public_key, send_secret_key, nonce, temp, length + 1,
		1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + packet);

	if (len == -1)
		return -1;

	packet[0] = NET_PACKET_CRYPTO;
	memcpy(packet + 1, recv_public_key, crypto_box_PUBLICKEYBYTES);
	memcpy(packet + 1 + crypto_box_PUBLICKEYBYTES, send_public_key, crypto_box_PUBLICKEYBYTES);

	return len + 1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES;
}


int CryptoCore::encrypt_data(const uint8_t* public_key, const uint8_t* secret_key, const uint8_t* nonce,	const uint8_t* plain, uint32_t length, uint8_t* encrypted)
{
	if (!public_key || !secret_key)
		return -1;
	uint8_t k[crypto_box_BEFORENMBYTES];
	encrypt_precompute(public_key, secret_key, k);
	int ret = encrypt_data_symmetric(k, nonce, plain, length, encrypted);
	sodium_memzero(k, sizeof k);
	return ret;
}

int CryptoCore::decrypt_data(const uint8_t* public_key, const uint8_t* secret_key, const uint8_t* nonce,const uint8_t* encrypted, uint32_t length, uint8_t* plain)
{
	if (!public_key || !secret_key)
		return -1;

	uint8_t k[crypto_box_BEFORENMBYTES];
	encrypt_precompute(public_key, secret_key, k);
	int ret =decryptDataSymmetric(k, nonce, encrypted, length, plain);
	sodium_memzero(k, sizeof k);
	return ret;
}



/* Puts the senders public key in the request in public_key, the data from the request in data if a friend or ping request was sent to us and returns the length of the data.
 * packet is the request packet and length is its length.
 *将发件人公钥放入public_key中的请求中，如果朋友或ping请求被发送给我们，请求数据来自数据，并返回数据的长度。 packet是请求包，length是其长度。
 *  return -1 if not valid request.
 */
int CryptoCore::handle_request(const uint8_t* self_public_key, const uint8_t* self_secret_key, uint8_t* public_key, uint8_t* data,
	uint8_t* request_id, const uint8_t* packet, uint16_t length)
{
	if (!self_public_key || !public_key || !data || !request_id || !packet)
		return -1;

	if (length <= crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + 1 + crypto_box_MACBYTES ||
		length > MAX_CRYPTO_REQUEST_SIZE)
		return -1;

	if (publicKeyCmp(packet + 1, self_public_key) != 0)
		return -1;

	memcpy(public_key, packet + 1 + crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	const uint8_t * nonce = packet + 1 + crypto_box_PUBLICKEYBYTES * 2;
	uint8_t temp[MAX_CRYPTO_REQUEST_SIZE]; // FIXME sodium_memzero before exit function
	int len1 = decrypt_data(public_key, self_secret_key, nonce,
		packet + 1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES,
		length - (crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + 1), temp);

	if (len1 == -1 || len1 == 0)
		return -1;

	request_id[0] = temp[0];
	--len1;
	memcpy(data, temp + 1, len1);
	return len1;
}


/* Fill a key crypto_box_KEYBYTES big with random bytes 用随机字节填充密钥crypto_box_KEYBYTES big*/
void CryptoCore::new_symmetric_key(uint8_t* key)
{
	randombytes(key, crypto_box_KEYBYTES);
}


/* Increment the given nonce by 1. */
void increment_nonce(uint8_t* nonce)
{
	/* FIXME use increment_nonce_number(nonce, 1) or sodium_increment (change to little endian)
	 * NOTE don't use breaks inside this loop
	 * In particular, make sure, as far as possible,
	 * that loop bounds and their potential underflow or overflow
	 * are independent of user-controlled input (you may have heard of the Heartbleed bug).
	 */
	uint32_t i = crypto_box_NONCEBYTES;
	uint_fast16_t carry = 1U;

	for (; i != 0; --i) {
		carry += (uint_fast16_t)nonce[i - 1];
		nonce[i - 1] = (uint8_t)carry;
		carry >>= 8;
	}
}

/* increment the given nonce by num */
void increment_nonce_number(uint8_t* nonce, uint32_t host_order_num)
{
	/* NOTE don't use breaks inside this loop
	 * In particular, make sure, as far as possible,
	 * that loop bounds and their potential underflow or overflow
	 * are independent of user-controlled input (you may have heard of the Heartbleed bug).
	 */
	const uint32_t big_endian_num = htonl(host_order_num);
	const uint8_t* const num_vec = (const uint8_t*)& big_endian_num;
	uint8_t num_as_nonce[crypto_box_NONCEBYTES] = { 0 };
	num_as_nonce[crypto_box_NONCEBYTES - 4] = num_vec[0];
	num_as_nonce[crypto_box_NONCEBYTES - 3] = num_vec[1];
	num_as_nonce[crypto_box_NONCEBYTES - 2] = num_vec[2];
	num_as_nonce[crypto_box_NONCEBYTES - 1] = num_vec[3];

	uint32_t i = crypto_box_NONCEBYTES;
	uint_fast16_t carry = 0U;

	for (; i != 0; --i) {
		carry += (uint_fast16_t)nonce[i - 1] + (uint_fast16_t)num_as_nonce[i - 1];
		nonce[i - 1] = (unsigned char)carry;
		carry >>= 8;
	}
}


/* Fill the given nonce with random bytes. */
void random_nonce(uint8_t* nonce)
{
	randombytes(nonce, crypto_box_NONCEBYTES);
}