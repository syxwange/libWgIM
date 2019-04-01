#pragma once

#include <QObject>

#include "network.h"
#include <sodium.h>



#define crypto_box_KEYBYTES (crypto_box_BEFORENMBYTES)

#define MAX_CRYPTO_REQUEST_SIZE 1024

#define CRYPTO_PACKET_FRIEND_REQ    32  /* Friend request crypto packet ID. */
#define CRYPTO_PACKET_HARDENING     48  /* Hardening crypto packet ID. */
#define CRYPTO_PACKET_DHTPK         156
#define CRYPTO_PACKET_NAT_PING      254 /* NAT ping crypto packet ID. */

class CryptoCore : public QObject
{
	Q_OBJECT

public:
	CryptoCore(QObject *parent=nullptr);
	~CryptoCore();

	static int publicKeyCmp(const uint8_t* pk1, const uint8_t* pk2);
	static void encryptPrecompute(const uint8_t* public_key, const uint8_t* secret_key, uint8_t* enc_key);
	static void newNonce(uint8_t* nonce);
	static int encryptDataSymmetric(const uint8_t* secret_key, const uint8_t* nonce, const uint8_t* plain, uint32_t length, uint8_t* encrypted);
	static int decryptDataSymmetric(const uint8_t* secret_key, const uint8_t* nonce, const uint8_t* encrypted, uint32_t length, uint8_t* plain);
	static int create_request(const uint8_t* send_public_key, const uint8_t* send_secret_key, uint8_t* packet, const uint8_t* recv_public_key,
		const uint8_t* data, uint32_t length, uint8_t request_id);

	static int encrypt_data(const uint8_t* public_key, const uint8_t* secret_key, const uint8_t* nonce, const uint8_t* plain, uint32_t length, uint8_t* encrypted);
private:
	static void CryptoCore::randomNonce(uint8_t* nonce);
};
