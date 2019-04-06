#pragma once


#include "dht.h"

/* Interval in seconds between LAN discovery packet sending. */
#define LAN_DISCOVERY_INTERVAL 10

/* Send a LAN discovery pcaket to the broadcast address with port port. */
int send_LANdiscovery(uint16_t port, DHT* dht);

/* Sets up packet handlers. */
void LANdiscovery_init(DHT* dht);

/* Clear packet handlers. */
void LANdiscovery_kill(DHT* dht);

/* Is IP a local ip or not. */
bool Local_ip(IP ip);

/* checks if a given IP isn't routable
 *
 *  return 0 if ip is a LAN ip.
 *  return -1 if it is not.
 */
//int LAN_ip(IP ip);