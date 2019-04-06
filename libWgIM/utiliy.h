#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <stdlib.h>
#include <string.h>

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


void host_to_net(uint8_t* num, uint16_t numbytes);
#define net_to_host(x, y) host_to_net(x, y)

uint16_t lendian_to_host16(uint16_t lendian);
#define host_tolendian16(x) lendian_to_host16(x)



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
int ipport_isset(const IP_Port* ipport);

/////===========================LAN
int LAN_ip(IP ip);
bool Local_ip(IP ip);


int create_recursive_mutex(pthread_mutex_t* mutex);
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



///////list///////////////////////////////

typedef struct {
	uint32_t n; //number of elements
	uint32_t capacity; //number of elements memory is allocated for
	uint32_t element_size; //size of the elements
	uint8_t* data; //array of elements
	int* ids; //array of element ids
} BS_LIST;

/* Initialize a list, element_size is the size of the elements in the list and
 * initial_capacity is the number of elements the memory will be initially allocated for
 *
 * return value:
 *  1 : success
 *  0 : failure
 */
int bs_list_init(BS_LIST* list, uint32_t element_size, uint32_t initial_capacity);

/* Free a list initiated with list_init */
void bs_list_free(BS_LIST* list);

/* Retrieve the id of an element in the list
 *
 * return value:
 *  >= 0 : id associated with data
 *  -1   : failure
 */
int bs_list_find(const BS_LIST* list, const uint8_t* data);

/* Add an element with associated id to the list
 *
 * return value:
 *  1 : success
 *  0 : failure (data already in list)
 */
int bs_list_add(BS_LIST* list, const uint8_t* data, int id);

/* Remove element from the list
 *
 * return value:
 *  1 : success
 *  0 : failure (element not found or id does not match)
 */
int bs_list_remove(BS_LIST* list, const uint8_t* data, int id);

/* Removes the memory overhead
 *
 * return value:
 *  1 : success
 *  0 : failure
 */
int bs_list_trim(BS_LIST* list);


void host_to_net(uint8_t* num, uint16_t numbytes);
