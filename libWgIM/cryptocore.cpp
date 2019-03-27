#include "cryptocore.h"

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