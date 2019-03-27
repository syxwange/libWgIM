
#include <time.h>

#include "utiliy.h"
#include <sodium.h>
#include "cryptocore.h"

/* don't call into system billions of times for no reason */
uint64_t Utiliy::unixTimeValue=0;
uint64_t Utiliy::unixBaseTimeValue=0;
uint64_t Utiliy::lastMonotime=0;
uint64_t Utiliy::addMonotime=0;

void Utiliy::unixTimeUpdate()
{
	if (unixBaseTimeValue == 0)
	{		
		unixBaseTimeValue = (time(nullptr) - (currentTimeMonotonic() / 1000ULL));
	}		
	unixTimeValue = (currentTimeMonotonic() / 1000ULL) + unixTimeValue;
}

/* return current monotonic time in milliseconds (ms). */
uint64_t Utiliy::currentTimeMonotonic(void)
{
	uint64_t time;
	time = GetTickCount64() + addMonotime;
	if (time < lastMonotime)
	{ /* Prevent time from ever decreasing because of 32 bit wrap. */
		uint32_t add = ~0;
		addMonotime += add;
		time += add;
	}
	lastMonotime = time;
	return time;
}


/* don't call into system billions of times for no reason 不要无缘无故地呼叫系统数十亿次*/
static uint64_t unix_time_value;
static uint64_t unix_base_time_value;
static uint64_t last_monotime;
static uint64_t add_monotime;


/* return current monotonic time in milliseconds (ms). 返回电脑启动到当前时间，以毫秒（ms）为单位*/
uint64_t current_time_monotonic(void)
{
	uint64_t time;
	time = (uint64_t)GetTickCount64() + add_monotime;
	if (time < last_monotime) { /* Prevent time from ever decreasing because of 32 bit wrap. */
		uint32_t add = ~0;
		add_monotime += add;
		time += add;
	}
	last_monotime = time;
	return time;
}

void unix_time_update()
{
	if (unix_base_time_value == 0)
		unix_base_time_value = ((uint64_t)time(NULL) - (current_time_monotonic() / 1000ULL));

	unix_time_value = (current_time_monotonic() / 1000ULL) + unix_base_time_value;
}

uint64_t unix_time()
{
	return unix_time_value;
}

int is_timeout(uint64_t timestamp, uint64_t timeout)
{
	return timestamp + timeout <= unix_time();
}

uint64_t random_64b(void)
{
	uint64_t randnum;
	randombytes((uint8_t*)& randnum, sizeof(randnum));
	return randnum;
}

bool id_equal(const uint8_t* dest, const uint8_t* src)
{
	return CryptoCore::publicKeyCmp(dest, src) == 0;	
}

uint32_t id_copy(uint8_t* dest, const uint8_t* src)
{
	memcpy(dest, src, crypto_box_PUBLICKEYBYTES);
	return crypto_box_PUBLICKEYBYTES;
}


/* checks if ip is valid */
bool  ip_isset(const IP* ip)
{
	if (!ip)
		return 0;

	return (ip->family != 0);
}

/* nulls out ip */
void ip_reset(IP* ip)
{
	if (!ip)
		return;
	memset(ip, 0, sizeof(IP));
}

/* copies an ip_port structure (careful about direction!) */
void ipport_copy(IP_Port* target, const IP_Port* source)
{
	if (!source || !target)
		return;

	memcpy(target, source, sizeof(IP_Port));
}

/* ip_equal
 *  compares two IPAny structures *  unset means unequal
 * returns 0 when not equal or when uninitialized */
int ip_equal(const IP* a, const IP* b)
{
	if (!a || !b)
		return 0;

	/* same family */
	if (a->family == b->family) {
		if (a->family == AF_INET)
			return (a->ip4.in_addr.s_addr == b->ip4.in_addr.s_addr);
		else if (a->family == AF_INET6)
			return a->ip6.uint64[0] == b->ip6.uint64[0] && a->ip6.uint64[1] == b->ip6.uint64[1];
		else
			return 0;
	}

	/* different family: check on the IPv6 one if it is the IPv4 one embedded */
	if ((a->family == AF_INET) && (b->family == AF_INET6)) {
		if (IPV6_IPV4_IN_V6(b->ip6))
			return (a->ip4.in_addr.s_addr == b->ip6.uint32[3]);
	}
	else if ((a->family == AF_INET6) && (b->family == AF_INET)) {
		if (IPV6_IPV4_IN_V6(a->ip6))
			return (a->ip6.uint32[3] == b->ip4.in_addr.s_addr);
	}

	return 0;
}


/* ipport_equal *  compares two IPAny_Port structures *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ipport_equal(const IP_Port* a, const IP_Port* b)
{
	if (!a || !b)
		return 0;

	if (!a->port || (a->port != b->port))
		return 0;
	
	return ip_equal(&a->ip, &b->ip);
}





/* Compares pk1 and pk2 with pk. *
 *  return 0 if both are same distance.
 *  return 1 if pk1 is closer.
 *  return 2 if pk2 is closer.
 */
int id_closest(const uint8_t* pk, const uint8_t* pk1, const uint8_t* pk2)
{
	size_t   i;
	uint8_t distance1, distance2;
	for (i = 0; i < crypto_box_PUBLICKEYBYTES; ++i) {

		distance1 = pk[i] ^ pk1[i];
		distance2 = pk[i] ^ pk2[i];

		if (distance1 < distance2)
			return 1;
		if (distance1 > distance2)
			return 2;
	}
	return 0;
}


///===Ping_Array=========================================================

static void clear_entry(Ping_Array* array, uint32_t index)
{
	free(array->entries[index].data);
	array->entries[index].data = NULL;
	array->entries[index].length =
		array->entries[index].time =
		array->entries[index].ping_id = 0;
}

/* Clear timed out entries.
 */
static void ping_array_clear_timedout(Ping_Array* array)
{
	while (array->last_deleted != array->last_added) {
		uint32_t index = array->last_deleted % array->total_size;

		if (!is_timeout(array->entries[index].time, array->timeout))
			break;

		clear_entry(array, index);
		++array->last_deleted;
	}
}

/* Add a data with length to the Ping_Array list and return a ping_id.
 *
 * return ping_id on success.
 * return 0 on failure.
 */
uint64_t ping_array_add(Ping_Array* array, const uint8_t* data, uint32_t length)
{
	ping_array_clear_timedout(array);
	uint32_t index = array->last_added % array->total_size;

	if (array->entries[index].data != NULL) {
		array->last_deleted = array->last_added - array->total_size;
		clear_entry(array, index);
	}

	array->entries[index].data = malloc(length);

	if (array->entries[index].data == NULL)
		return 0;

	memcpy(array->entries[index].data, data, length);
	array->entries[index].length = length;
	array->entries[index].time = unix_time();
	++array->last_added;
	uint64_t ping_id = random_64b();
	ping_id /= array->total_size;
	ping_id *= array->total_size;
	ping_id += index;

	if (ping_id == 0)
		ping_id += array->total_size;

	array->entries[index].ping_id = ping_id;
	return ping_id;
}


/* Check if ping_id is valid and not timed out.
 *
 * On success, copies the data into data of length,
 *
 * return length of data copied on success.
 * return -1 on failure.
 */
int ping_array_check(uint8_t * data, uint32_t length, Ping_Array * array, uint64_t ping_id)
{
	if (ping_id == 0)
		return -1;

	uint32_t index = ping_id % array->total_size;

	if (array->entries[index].ping_id != ping_id)
		return -1;

	if (is_timeout(array->entries[index].time, array->timeout))
		return -1;

	if (array->entries[index].length > length)
		return -1;

	if (array->entries[index].data == NULL)
		return -1;

	memcpy(data, array->entries[index].data, array->entries[index].length);
	uint32_t len = array->entries[index].length;
	clear_entry(array, index);
	return len;
}

/* Initialize a Ping_Array.
 * size represents the total size of the array and should be a power of 2.
 * timeout represents the maximum timeout in seconds for the entry.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int ping_array_init(Ping_Array * empty_array, uint32_t size, uint32_t timeout)
{
	if (size == 0 || timeout == 0 || empty_array == NULL)
		return -1;

	empty_array->entries = (Ping_Array_Entry *)calloc(size, sizeof(Ping_Array_Entry));

	if (empty_array->entries == NULL)
		return -1;

	empty_array->last_deleted = empty_array->last_added = 0;
	empty_array->total_size = size;
	empty_array->timeout = timeout;
	return 0;
}

/* Free all the allocated memory in a Ping_Array.
 */
void ping_array_free_all(Ping_Array * array)
{
	while (array->last_deleted != array->last_added) {
		uint32_t index = array->last_deleted % array->total_size;
		clear_entry(array, index);
		++array->last_deleted;
	}

	free(array->entries);
	array->entries = NULL;
}
