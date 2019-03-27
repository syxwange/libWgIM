#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "libwgim_global.h"
#include <pthread.h>
#include "network.h"

#define _CRT_NO_TIME_T
#define MIN(a,b) (((a)<(b))?(a):(b))
#define PAIR(TYPE1__, TYPE2__) struct { TYPE1__ first; TYPE2__ second; }

class LIBWGIM_EXPORT Utiliy
{

public:
	static void unixTimeUpdate();

	static uint64_t currentTimeMonotonic(void);

	static uint64_t unixTimeValue;
	static uint64_t unixBaseTimeValue;
	static uint64_t lastMonotime;
	static uint64_t addMonotime;
};

uint64_t current_time_monotonic(void);
void unix_time_update();
uint64_t unix_time();
int is_timeout(uint64_t timestamp, uint64_t timeout);
bool id_equal(const uint8_t* dest, const uint8_t* src);
uint32_t id_copy(uint8_t* dest, const uint8_t* src);
///==================================
uint64_t random_64b(void);
bool  ip_isset(const IP* ip);
void ip_reset(IP* ip);
void ipport_copy(IP_Port* target, const IP_Port* source);
int ipport_equal(const IP_Port* a, const IP_Port* b);
int ip_equal(const IP* a, const IP* b);
int id_closest(const uint8_t* pk, const uint8_t* pk1, const uint8_t* pk2);
const char* ip_ntoa(const IP* ip);


/////===========================LAN
int LAN_ip(IP ip);
bool Local_ip(IP ip);
///===Ping_Array====start=====================================================

typedef struct {
	void* data;
	uint32_t length;
	uint64_t time;
	uint64_t ping_id;
} Ping_Array_Entry;


typedef struct {
	Ping_Array_Entry* entries;

	uint32_t last_deleted; /* number representing the next entry to be deleted. */
	uint32_t last_added; /* number representing the last entry to be added. */
	uint32_t total_size; /* The length of entries */
	uint32_t timeout; /* The timeout after which entries are cleared. */
} Ping_Array;


/* Add a data with length to the Ping_Array list and return a ping_id.
 *
 * return ping_id on success.
 * return 0 on failure.
 */
uint64_t ping_array_add(Ping_Array* array, const uint8_t* data, uint32_t length);

/* Check if ping_id is valid and not timed out.
 *
 * On success, copies the data into data of length,
 *
 * return length of data copied on success.
 * return -1 on failure.
 */
int ping_array_check(uint8_t* data, uint32_t length, Ping_Array* array, uint64_t ping_id);

/* Initialize a Ping_Array.
 * size represents the total size of the array and should be a power of 2.
 * timeout represents the maximum timeout in seconds for the entry.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int ping_array_init(Ping_Array* empty_array, uint32_t size, uint32_t timeout);

/* Free all the allocated memory in a Ping_Array.
 */
void ping_array_free_all(Ping_Array* array);

///===Ping_Array===end===================================================