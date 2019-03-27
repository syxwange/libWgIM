#pragma once

#include <QObject>

#include "network.h"
#include <sodium.h>



#define crypto_box_KEYBYTES (crypto_box_BEFORENMBYTES)

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

private:
	static void CryptoCore::randomNonce(uint8_t* nonce);
};
