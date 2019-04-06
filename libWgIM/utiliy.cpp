
#include <time.h>

#include "utiliy.h"
#include <sodium.h>
#include "cryptocore.h"


#pragma comment(lib,"../packages/pthreads.2.9.1.4/build/native/lib/v110/x64/Release/dynamic/stdcall/libpthread-stdcall.lib")

/* don't call into system billions of times for no reason 不要无缘无故地呼叫系统数十亿次*/
uint64_t Utiliy::unixTimeValue=0;              //1970 年 1 月 1 日(00: 00:00) 到当前和秒数
uint64_t Utiliy::unixBaseTimeValue=0;       //1970 年 1 月 1 日(00: 00:00) 到电脑开机的秒数
uint64_t Utiliy::lastMonotime=0;               //电脑开机的毫秒数
uint64_t Utiliy::addMonotime=0;

//time(nullptr)函数将返回 自 1970 年 1 月 1 日(00: 00:00) 的秒数，
void Utiliy::unixTimeUpdate()
{
	if (unixBaseTimeValue == 0)
	{		
		unixBaseTimeValue = (time(nullptr) - (currentTimeMonotonic() / 1000ULL));
	}		
	unixTimeValue = (currentTimeMonotonic() / 1000ULL) + unixBaseTimeValue;
}

/* return current monotonic time in milliseconds (ms). 
 * GetTickCount64()得到自系统启动以来经过的毫秒数。
*/
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
static uint64_t unix_time_value;                      //1970 年 1 月 1 日(00: 00:00) 到当前和秒数
static uint64_t unix_base_time_value;             //1970 年 1 月 1 日(00: 00:00) 到电脑开机的秒数
static uint64_t last_monotime;                       //电脑开机的毫秒数
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


void host_to_net(uint8_t* num, uint16_t numbytes)
{
#ifndef WORDS_BIGENDIAN
	uint32_t i;
	uint8_t *buff=new uint8_t[numbytes];

	for (i = 0; i < numbytes; ++i) {
		buff[i] = num[numbytes - i - 1];
	}

	memcpy(num, buff, numbytes);
#endif

	delete[]buff;
	return;
}

uint16_t lendian_to_host16(uint16_t lendian)
{
#ifdef WORDS_BIGENDIAN
	return  (lendian << 8) | (lendian >> 8);
#else
	return lendian;
#endif
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


/* checks if ip is valid */
int ipport_isset(const IP_Port* ipport)
{
	if (!ipport)
		return 0;

	if (!ipport->port)
		return 0;

	return ip_isset(&ipport->ip);
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
	for (i = 0; i < crypto_box_PUBLICKEYBYTES; ++i)
	{

		distance1 = pk[i] ^ pk1[i];
		distance2 = pk[i] ^ pk2[i];

		if (distance1 < distance2)
			return 1;
		if (distance1 > distance2)
			return 2;
	}
	return 0;
}



/* ip_ntoa
 *   converts ip into a string  uses a static buffer, so mustn't used multiple times in the same output 
 *   IPv6 addresses are enclosed into square brackets, i.e. "[IPv6]"  writes error message into the buffer on error
 * 将ip转换为字符串使用静态缓冲区，因此不得在同一输出中多次使用   IPv6地址括在方括号中即“[IPv6]”，在出错时将错误消息写入缓冲区
 */
 /* there would be INET6_ADDRSTRLEN, but it might be too short for the error message */
static char addresstext[96]; // FIXME magic number. Why not INET6_ADDRSTRLEN ?
const char* ip_ntoa(const IP* ip)
{
	if (ip) {
		if (ip->family == AF_INET) {
			/* returns standard quad-dotted notation */
			struct in_addr* addr = (struct in_addr*) & ip->ip4;

			addresstext[0] = 0;
			inet_ntop(ip->family, addr, addresstext, sizeof(addresstext));
		}
		else if (ip->family == AF_INET6) {
			/* returns hex-groups enclosed into square brackets */
			struct in6_addr* addr = (struct in6_addr*) & ip->ip6;

			addresstext[0] = '[';
			inet_ntop(ip->family, addr, &addresstext[1], sizeof(addresstext) - 3);
			size_t len = strlen(addresstext);
			addresstext[len] = ']';
			addresstext[len + 1] = 0;
		}
		else
			snprintf(addresstext, sizeof(addresstext), "(IP invalid, family %u)", ip->family);
	}
	else
		snprintf(addresstext, sizeof(addresstext), "(IP invalid: NULL)");

	/* brute force protection against lacking termination */
	addresstext[sizeof(addresstext) - 1] = 0;
	return addresstext;
}


////////////////////LAN================
/*  return 0 if ip is a LAN ip.
 *  return -1 if it is not.
 */
int LAN_ip(IP ip)
{
	if (Local_ip(ip))
		return 0;

	if (ip.family == AF_INET) {
		IP4 ip4 = ip.ip4;

		/* 10.0.0.0 to 10.255.255.255 range. */
		if (ip4.uint8[0] == 10)
			return 0;

		/* 172.16.0.0 to 172.31.255.255 range. */
		if (ip4.uint8[0] == 172 && ip4.uint8[1] >= 16 && ip4.uint8[1] <= 31)
			return 0;

		/* 192.168.0.0 to 192.168.255.255 range. */
		if (ip4.uint8[0] == 192 && ip4.uint8[1] == 168)
			return 0;

		/* 169.254.1.0 to 169.254.254.255 range. */
		if (ip4.uint8[0] == 169 && ip4.uint8[1] == 254 && ip4.uint8[2] != 0
			&& ip4.uint8[2] != 255)
			return 0;

		/* RFC 6598: 100.64.0.0 to 100.127.255.255 (100.64.0.0/10)
		 * (shared address space to stack another layer of NAT) */
		if ((ip4.uint8[0] == 100) && ((ip4.uint8[1] & 0xC0) == 0x40))
			return 0;

	}
	else if (ip.family == AF_INET6) {

		/* autogenerated for each interface: FE80::* (up to FEBF::*)
		   FF02::1 is - according to RFC 4291 - multicast all-nodes link-local */
		if (((ip.ip6.uint8[0] == 0xFF) && (ip.ip6.uint8[1] < 3) && (ip.ip6.uint8[15] == 1)) ||
			((ip.ip6.uint8[0] == 0xFE) && ((ip.ip6.uint8[1] & 0xC0) == 0x80)))
			return 0;

		/* embedded IPv4-in-IPv6 */
		if (IPV6_IPV4_IN_V6(ip.ip6)) {
			IP ip4;
			ip4.family = AF_INET;
			ip4.ip4.uint32 = ip.ip6.uint32[3];
			return LAN_ip(ip4);
		}
	}

	return -1;
}

/* Is IP a local ip or not. */
bool Local_ip(IP ip)
{
	if (ip.family == AF_INET) {
		IP4 ip4 = ip.ip4;

		/* Loopback. */
		if (ip4.uint8[0] == 127)
			return 1;
	}
	else {
		/* embedded IPv4-in-IPv6 */
		if (IPV6_IPV4_IN_V6(ip.ip6)) {
			IP ip4;
			ip4.family = AF_INET;
			ip4.ip4.uint32 = ip.ip6.uint32[3];
			return Local_ip(ip4);
		}

		/* localhost in IPv6 (::1) */
		if (ip.ip6.uint64[0] == 0 && ip.ip6.uint32[2] == 0 && ip.ip6.uint32[3] == htonl(1))
			return 1;
	}

	return 0;
}




///===Ping_Array=========================================================

static void clear_entry(Ping_Array* array, uint32_t index)
{
	free(array->entries[index].data);
	array->entries[index].data = NULL;
	array->entries[index].length = array->entries[index].time =	array->entries[index].ping_id = 0;
}

/* Clear timed out entries.
 */
static void ping_array_clear_timedout(Ping_Array* array)
{
	while (array->last_deleted != array->last_added)
	{
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
 * size represents the total size of the array and should be a power of 2. timeout represents the maximum timeout in seconds for the entry.
 * 初始化Ping_Array。 size表示阵列的总大小，应该是2的幂.timeout表示条目的最大超时（秒）。
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
	while (array->last_deleted != array->last_added) 
	{
		uint32_t index = array->last_deleted % array->total_size;
		clear_entry(array, index);
		++array->last_deleted;
	}
	free(array->entries);
	array->entries = NULL;
}

/////////////////////////list=======================================
#define INDEX(i) (~i)

/* Find data in list
 *
 * return value:
 *  >= 0 : index of data in array
 *  < 0  : no match, returns index (return value is INDEX(index)) where
 *         the data should be inserted
 */
static int find(const BS_LIST* list, const uint8_t* data)
{
	//should work well, but could be improved
	if (list->n == 0) {
		return INDEX(0);
	}

	uint32_t i = list->n / 2; //current position in the array
	uint32_t delta = i / 2;   //how much we move in the array

	if (!delta) {
		delta = 1;
	}

	int d = -1; //used to determine if closest match is found
	//closest match is found if we move back to where we have already been

	while (1) {
		int r = memcmp(data, list->data + list->element_size * i, list->element_size);

		if (r == 0) {
			return i;
		}

		if (r > 0) {
			//data is greater
			//move down
			i += delta;

			if (d == 0 || i == list->n) {
				//reached bottom of list, or closest match
				return INDEX(i);
			}

			delta = (delta) / 2;

			if (delta == 0) {
				delta = 1;
				d = 1;
			}
		}
		else {
			//data is smaller
			if (d == 1 || i == 0) {
				//reached top or list or closest match
				return INDEX(i);
			}

			//move up
			i -= delta;

			delta = (delta) / 2;

			if (delta == 0) {
				delta = 1;
				d = 0;
			}
		}
	}
}

/* Resized the list list
 *
 * return value:
 *  1 : success
 *  0 : failure
 */
static int resize(BS_LIST* list, uint32_t new_size)
{
	void* p;

	p = realloc(list->data, list->element_size * new_size);

	if (!p) {
		return 0;
	}
	else {
		list->data = (uint8_t *)p;
	}

	p = realloc(list->ids, sizeof(int) * new_size);

	if (!p) {
		return 0;
	}
	else {
		list->ids =(int *) p;
	}

	return 1;
}


int bs_list_init(BS_LIST* list, uint32_t element_size, uint32_t initial_capacity)
{
	//set initial values
	list->n = 0;
	list->element_size = element_size;
	list->capacity = 0;
	list->data = NULL;
	list->ids = NULL;

	if (initial_capacity != 0) {
		if (!resize(list, initial_capacity)) {
			return 0;
		}
	}

	list->capacity = initial_capacity;

	return 1;
}

void bs_list_free(BS_LIST* list)
{
	//free both arrays
	free(list->data);
	free(list->ids);
}

int bs_list_find(const BS_LIST* list, const uint8_t* data)
{
	int r = find(list, data);

	//return only -1 and positive values
	if (r < 0) {
		return -1;
	}

	return list->ids[r];
}

int bs_list_add(BS_LIST* list, const uint8_t* data, int id)
{
	//find where the new element should be inserted
	//see: return value of find()
	int i = find(list, data);

	if (i >= 0) {
		//already in list
		return 0;
	}

	i = ~i;

	//increase the size of the arrays if needed
	if (list->n == list->capacity) {
		// 1.5 * n + 1
		const uint32_t new_capacity = list->n + list->n / 2 + 1;

		if (!resize(list, new_capacity)) {
			return 0;
		}

		list->capacity = new_capacity;
	}

	//insert data to element array
	memmove(list->data + (i + 1) * list->element_size, list->data + i * list->element_size,
		(list->n - i) * list->element_size);
	memcpy(list->data + i * list->element_size, data, list->element_size);

	//insert id to id array
	memmove(&list->ids[i + 1], &list->ids[i], (list->n - i) * sizeof(int));
	list->ids[i] = id;

	//increase n
	list->n++;

	return 1;
}

int bs_list_remove(BS_LIST * list, const uint8_t * data, int id)
{
	int i = find(list, data);

	if (i < 0) {
		return 0;
	}

	if (list->ids[i] != id) {
		//this should never happen
		return 0;
	}

	//decrease the size of the arrays if needed
	if (list->n < list->capacity / 2) {
		const uint32_t new_capacity = list->capacity / 2;

		if (resize(list, new_capacity)) {
			list->capacity = new_capacity;
		}
	}

	list->n--;

	memmove(list->data + i * list->element_size, list->data + (i + 1) * list->element_size,
		(list->n - i) * list->element_size);
	memmove(&list->ids[i], &list->ids[i + 1], (list->n - i) * sizeof(int));

	return 1;
}

int bs_list_trim(BS_LIST * list)
{
	if (!resize(list, list->n)) {
		return 0;
	}

	list->capacity = list->n;
	return 1;
}



int create_recursive_mutex(pthread_mutex_t* mutex)
{
	pthread_mutexattr_t attr;

	if (pthread_mutexattr_init(&attr) != 0)
		return -1;

	if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
		pthread_mutexattr_destroy(&attr);
		return -1;
	}

	/* Create queue mutex */
	if (pthread_mutex_init(mutex, &attr) != 0) {
		pthread_mutexattr_destroy(&attr);
		return -1;
	}

	pthread_mutexattr_destroy(&attr);

	return 0;
}

