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
};
