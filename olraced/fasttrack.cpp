/*
 * fasttrack race detector
 * forked from txgo
 * Nov 2015 Tong Zhang<ztong@vt.edu>
 */


#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h> /* offsetof */
#include <unistd.h> /* syscall */
#include <map>
#include <set>
#include "fasttrack.h"

/****************************************************************************************
 * CONFIGURABLE PARAMETERS 
 ***************************************************************************************/

/* # OF THREADS */
//#define THREAD_MAX 16 //WE USE 4 BIT TO REPRESENT TID ---> MAX=16
#define THREAD_MAX 256 //WE USE 8 BIT TO REPRESENT TID ---> MAX=256

/* BY DEFUALT, WORD GRANULARITY DETECTION*/
#define DETECTION_UNIT_SIZE (__WORDSIZE/8) // __WORDSIZE 32 vs 64
//#define DETECTION_UNIT_SIZE 1 /* BYTE */
//#define DETECTION_UNIT_SIZE 4 
//#define DETECTION_UNIT_SIZE 8

/* DEBUG */
//#define USE_DPRINT
//#define USE_ASSERT
//#define USE_VC_DEBUG

/****************************************************************************************
 * TYPEDEF & MACRO
 ***************************************************************************************/

using namespace std;

typedef unsigned long address_t;

#define INVALID_TID static_cast<tid_t>(-1)
#define INVALID_ADDR static_cast<address_t>(-1)

static int READ_SHARED = 0xfffffff; //28bits

typedef struct _clck_t
{
	unsigned int tid:4;
	unsigned int clck:28;
} clck_t;

typedef struct _thread_state_t
{
	volatile tid_t tid;
	clck_t vc[THREAD_MAX];
	//clck_t epoch;           // invariant: epoch == vc[tid] 
} thread_state_t;

typedef struct _var_state_t
{
	clck_t W;
	clck_t R;
	clck_t *Rvc;            // used iff R == READ_SHARED
	void* rip;
} var_state_t;

typedef struct _lock_state_t
{
	clck_t __dummy1;
	clck_t __dummy2;
	clck_t *vc;

} lock_state_t;

typedef struct _cond_state_t
{
	clck_t __dummy1;
	clck_t __dummy2;
	clck_t *vc;
} cond_state_t;

enum
{
	RACE_TYPE_INVALID,
	RACE_TYPE_RAW,
	RACE_TYPE_WAW,
	RACE_TYPE_WAR1,
	RACE_TYPE_WAR2,
};

// Used to align addresses
#define WORD_SIZE __WORDSIZE/8 /* 4 for 32bit 8 for 64bit arch */
#define UNIT_MASK(unit_size) (~((unit_size)-1))
#define UNIT_DOWN_ALIGN(addr,unit_size) ((addr) & UNIT_MASK(unit_size))
#define UNIT_UP_ALIGN(addr,unit_size) \
	(((addr)+(unit_size)-1) & UNIT_MASK(unit_size))

// Min/Max 
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

/****************************************************************************************
 * DEBUG
 ***************************************************************************************/

#ifdef USE_DPRINT
#define DPRINT(format, ...) do{ \
	for(int _i=0;_i<tid;_i++){printf("\t\t");}  \
	printf(format, __VA_ARGS__);                \
}while(0)
#else
#define DPRINT(...)
#endif

#ifdef USE_ASSERT
#define ASSERT(x)  do{if(!(x))printf("ASSERT FAIL!! line=%d\n",__LINE__);assert(x);}while(0)
#else
#define ASSERT(...)
#endif

/****************************************************************************************
 * GLOBALS
 ***************************************************************************************/
// metadata
static thread_state_t thread_state_map[THREAD_MAX];
static std::map<address_t, var_state_t *>  var_state_map;
static std::map<address_t, lock_state_t *>  lock_state_map;
static std::map<address_t, cond_state_t *>  cond_state_map;

//memory allocation info
map<void*,unsigned int> mem_db;

// race db
std::set<std::tuple<void* /*ins1_ip*/, void* /*ins2_id*/, int/*type*/> > race_db;

/****************************************************************************************
 * METADATA
 ***************************************************************************************/

thread_state_t *thread_state_get(tid_t tid)
{
	ASSERT(0<=tid && tid<THREAD_MAX);
	thread_state_t *thrd = &thread_state_map[tid];
	return thrd;
}

static var_state_t *var_state_get(address_t addr){
	std::map<address_t, var_state_t *>::iterator it = var_state_map.find(addr);
	if(it == var_state_map.end()){
		return NULL;
	}
	else{
		return (var_state_t *)it->second;
	}
}

static lock_state_t *lock_state_get(address_t addr){
	std::map<address_t, lock_state_t *>::iterator it = lock_state_map.find(addr);
	if(it == lock_state_map.end()){
		return NULL;
	}
	else{
		return (lock_state_t *)it->second;
	}
}

static cond_state_t *cond_state_get(address_t addr){
	std::map<address_t, cond_state_t *>::iterator it = cond_state_map.find(addr);
	if(it == cond_state_map.end()){
		return NULL;
	}
	else{
		return (cond_state_t *)it->second;
	}
}

/****************************************************************************************
 * REGION FILTER
 ***************************************************************************************/


void ft_mem_alloc(void *__addr, unsigned long size)
{

	address_t addr = (address_t)(uintptr_t)__addr;
	ASSERT(addr && size);
	mem_db[__addr] = size;
}

void ft_mem_free(void *__addr)
{

	address_t addr = (address_t)(uintptr_t)__addr;
	ASSERT(addr);


	unsigned long size = mem_db[__addr];
	mem_db.erase(__addr);

	address_t start_addr = UNIT_DOWN_ALIGN(addr, DETECTION_UNIT_SIZE);
	address_t end_addr = UNIT_UP_ALIGN(addr + size, DETECTION_UNIT_SIZE);

	for (address_t iaddr = start_addr; iaddr < end_addr; iaddr += DETECTION_UNIT_SIZE) {
		std::map<address_t, var_state_t *>::iterator it = var_state_map.find(iaddr);
		if (it != var_state_map.end()) {
			var_state_t *var = (var_state_t *)it->second;
			if(var->Rvc)
			{
				free(var->Rvc);
			}
			free(var);

			var_state_map.erase(it);
		}
	}

	for (address_t iaddr = start_addr; iaddr < end_addr; iaddr += DETECTION_UNIT_SIZE) {
		std::map<address_t, lock_state_t *>::iterator it = lock_state_map.find(iaddr);
		if(it != lock_state_map.end()){
			lock_state_t *lck = (lock_state_t *)it->second;
			if(lck->vc)
			{
				free(lck->vc);
			}
			free(lck);
			lock_state_map.erase(it);
		}
	}

	for (address_t iaddr = start_addr; iaddr < end_addr; iaddr += DETECTION_UNIT_SIZE) {
		std::map<address_t, cond_state_t *>::iterator it = cond_state_map.find(iaddr);
		if(it != cond_state_map.end()){
			cond_state_t *cnd = (cond_state_t *)it->second;
			if(cnd->vc)
			{
				free(cnd->vc);
			}
			free(cnd);
			cond_state_map.erase(it);
		}
	}

}

/****************************************************************************************
 * VECTOR CLOCK 
 ***************************************************************************************/

static void vc_join(clck_t *vc1, clck_t *vc2)
{
	int i;
	for(i=0;i<THREAD_MAX;i++)
	{
		vc1[i].clck = MAX (vc1[i].clck, vc2[i].clck);
	}
}

static void vc_copy(clck_t *vc1, clck_t *vc2)
{
	int i;
	for(i=0;i<THREAD_MAX;i++)
	{
		vc1[i].clck = vc2[i].clck;
	}
}

#define vc_inc(vc,i) do{vc[i].clck++;}while(0)

static int vc_is_ordered(tid_t tid, clck_t *vc1, clck_t *vc2)
{
	int ordered = 1;
	int i;

	for(i=0;i<THREAD_MAX;i++)
	{
		if(i!=tid)
		{
			if(vc1[i].clck > vc2[i].clck)
			{
				ordered = 0;
				break;
			}
		}
	}
	return ordered;
}

#ifdef USE_VC_DEBUG
static void VC_DEBUG(tid_t tid, const char *prefix, clck_t *vc)
{
	int i;
	char buf[256];
	sprintf(buf,"(");
	for(i=0;i<THREAD_MAX-1;i++)
	{
		sprintf(buf+strlen(buf),"%d,",vc[i].clck);
	}
	sprintf(buf+strlen(buf),"%d)",vc[THREAD_MAX-1].clck);
	assert(prefix);
	DPRINT("[%d] %s->vc%s\n",tid,prefix,buf);
}
#else
#define VC_DEBUG(...)
#endif

/****************************************************************************************
 * INIT
 ***************************************************************************************/

void ft_init()
{
	/* DON'T MAKE SYSCALL FOR NOW */
	printf("ft_init(): MAX_TH=%d, UNIT_SIZE=%d\n",
			THREAD_MAX,DETECTION_UNIT_SIZE);
}

void ft_fini()
{
	printf("===[ RACE SUMMARY ]===================================\n");

	std::set<std::tuple<void* /*ins1_id*/, void* /*ins2_id*/, int/*type*/> >::iterator it;
	for(it = race_db.begin(); it != race_db.end(); ++it){
		void* ins1_ip;
		void* ins2_ip;
		int race_type;

		std::tie(ins1_ip,ins2_ip,race_type) = *it;
		if(race_type == RACE_TYPE_RAW)
			printf("R(%p)-W(%p)\n",ins1_ip,ins2_ip);
		else if(race_type == RACE_TYPE_WAW)
			printf("W(%p)-W(%p)\n",ins1_ip,ins2_ip);
		else if(race_type == RACE_TYPE_WAR1)
			printf("W(%p)-R(%p)\n",ins1_ip,ins2_ip);
		else if(race_type == RACE_TYPE_WAR2)
			printf("W(%p)-R(%p) (shared reads)\n",ins1_ip,ins2_ip);
	}

	int i = 0;
	for(it = race_db.begin(); it != race_db.end(); ++it){
		void* ins1_ip;
		void* ins2_ip;
		int race_type;

		std::tie(ins1_ip,ins2_ip,race_type) = *it;
		if(ins1_ip<ins2_ip)
			printf("[%d]%p,%p\n",i,ins1_ip,ins2_ip);
		else 
			printf("[%d]%p,%p\n",i,ins2_ip,ins1_ip);
		i++;
	}
	printf("======================================================\n");
}

/****************************************************************************************
 * UNLOCK -> LOCK
 ***************************************************************************************/

void ft_before_unlock(void *__lock_addr, tid_t _tid)
{

	tid_t tid = _tid;
	address_t lock_addr = (address_t)(uintptr_t)__lock_addr;
	ASSERT(0<=tid && tid < THREAD_MAX);
	ASSERT(UNIT_DOWN_ALIGN(lock_addr, WORD_SIZE) == lock_addr);

	DPRINT("[%d] unlock(lock_addr:0x%lx)\n",tid,lock_addr);

	thread_state_t *thrd = thread_state_get(tid);
	ASSERT(thrd);

	lock_state_t *lck = lock_state_get(lock_addr);
	if(lck==NULL){
		lck = (lock_state_t *)calloc(1,sizeof(lock_state_t));
		ASSERT(lck);
		lck->vc = (clck_t *)calloc(1,sizeof(clck_t)*THREAD_MAX);
		ASSERT(lck->vc);
		lock_state_map[lock_addr] = lck;
	}

	VC_DEBUG(tid,"READ thrd",thrd->vc);
	vc_copy(lck->vc, thrd->vc);
	VC_DEBUG(tid,"COPY lock", lck->vc);
	vc_inc(thrd->vc, tid);
	VC_DEBUG(tid,"INC  thrd", thrd->vc);

} 

void ft_after_lock(void *__lock_addr, tid_t _tid)
{

	tid_t tid = _tid;
	address_t lock_addr = (address_t)(uintptr_t)__lock_addr;
	ASSERT(0<=tid && tid < THREAD_MAX);
	ASSERT(UNIT_DOWN_ALIGN(lock_addr, WORD_SIZE) == lock_addr);

	DPRINT("[%d] lock(lock_addr:0x%lx)\n",tid,lock_addr);

	thread_state_t *thrd = thread_state_get(tid);
	ASSERT(thrd);

	lock_state_t *lck = lock_state_get(lock_addr);
	if(lck==NULL){
		lck = (lock_state_t *)calloc(1,sizeof(lock_state_t));
		ASSERT(lck);
		lck->vc = (clck_t *)calloc(1,sizeof(clck_t)*THREAD_MAX);
		ASSERT(lck->vc);
		lock_state_map[lock_addr] = lck;
	}

	VC_DEBUG(tid,"READ thrd",thrd->vc);
	VC_DEBUG(tid,"READ lock",lck->vc);
	vc_join(thrd->vc, lck->vc);
	VC_DEBUG(tid,"JOIN thrd",thrd->vc);

}
/****************************************************************************************
 * THREAD_CREATE -> THREAD_INIT
 ***************************************************************************************/

void ft_after_thread_create(unsigned long child_pthread_id, tid_t _tid)
{

	tid_t tid = _tid;
	tid_t child_tid = child_pthread_id;
	ASSERT(0<=tid && tid < THREAD_MAX);
	ASSERT(0<=child_tid && child_tid < THREAD_MAX);

	DPRINT("[%d] thread_create(child_tid:%d)\n",tid,child_tid);

	thread_state_t *thrd = thread_state_get(tid);
	ASSERT(thrd);

	thread_state_t *child_thrd = thread_state_get(child_tid);
	ASSERT(child_thrd);

	// initialize child_thrd's vc on behalf
	vc_copy(child_thrd->vc, thrd->vc);
	vc_inc(child_thrd->vc,child_tid);
	// set the tid of child thread to wake it up!
	//DPRINT("[%d] thread_create: set child_thrd->tid=%d\n",tid,child_tid);
	child_thrd->tid = child_tid;

	vc_inc(thrd->vc,tid);
	VC_DEBUG(tid,"INC  thrd",thrd->vc);

}

void ft_after_thread_init(tid_t _tid)
{

	tid_t tid = _tid;
	ASSERT(0<=tid && tid < THREAD_MAX);

	DPRINT("[%d] thread_init()\n",tid);

	thread_state_t *thrd = thread_state_get(tid);
	ASSERT(thrd);
	/*
	 * who comes first initialize the vector clock
	 */
	thrd->tid = 0;
	vc_inc(thrd->vc,0);
} 

/****************************************************************************************
 * THREAD_EXIT -> THREAD_JOIN
 ***************************************************************************************/

void ft_before_thread_exit(tid_t tid)
{

	DPRINT("[%d] thread_exit()\n",tid);

	//VC_DEBUG(tid,"thrd",thrd->vc);
} 

void ft_after_thread_join(unsigned long child_pthread_id, tid_t _tid)
{

	tid_t tid = _tid;
	tid_t child_tid = child_pthread_id;
	ASSERT(0<=tid && tid < THREAD_MAX);
	ASSERT(0<=child_tid && child_tid < THREAD_MAX);

	DPRINT("[%d] thread_join(child_tid:%d)\n",tid,child_tid);

	thread_state_t *thrd = thread_state_get(tid);
	ASSERT(thrd);

	thread_state_t *child_thrd = thread_state_get(child_tid);
	ASSERT(child_thrd);

	VC_DEBUG(tid,"READ thrd",thrd->vc);
	VC_DEBUG(tid,"READ chrd",child_thrd->vc);
	vc_join(thrd->vc, child_thrd->vc);
	VC_DEBUG(tid,"JOIN thrd",thrd->vc);

}

/****************************************************************************************
 * SIGNAL -> WAIT
 ***************************************************************************************/

void ft_before_signal(void *__cond_addr, tid_t _tid)
{

	tid_t tid = _tid;
	address_t cond_addr = (address_t)(uintptr_t)__cond_addr;
	ASSERT(0<=tid && tid < THREAD_MAX);
	//ASSERT(UNIT_DOWN_ALIGN(cond_addr, WORD_SIZE) == cond_addr);

	DPRINT("[%d] signal(cond_addr:0x%lx)\n",tid,cond_addr);

	thread_state_t *thrd = thread_state_get(tid);
	ASSERT(thrd);

	cond_state_t *cnd = cond_state_get(cond_addr);
	if(cnd==NULL){
		cnd = (cond_state_t *)calloc(1,sizeof(cond_state_t));
		ASSERT(cnd);
		cnd->vc = (clck_t *)calloc(1,sizeof(clck_t)*THREAD_MAX);
		ASSERT(cnd->vc);
		cond_state_map[cond_addr] = cnd;
	}

	vc_copy(cnd->vc, thrd->vc);

	vc_inc(thrd->vc,tid);
	VC_DEBUG(tid,"INC  thrd",thrd->vc);

}

void ft_before_broadcast(void *__cond_addr, tid_t _tid)
{

	tid_t tid = _tid;
	address_t cond_addr = (address_t)(uintptr_t)__cond_addr;
	ASSERT(0<=tid && tid < THREAD_MAX);
	//ASSERT(UNIT_DOWN_ALIGN(cond_addr, WORD_SIZE) == cond_addr);

	DPRINT("[%d] broadcast(cond_addr:0x%lx)\n",tid,cond_addr);

	thread_state_t *thrd = thread_state_get(tid);
	ASSERT(thrd);

	cond_state_t *cnd = cond_state_get(cond_addr);
	if(cnd==NULL){
		cnd = (cond_state_t *)calloc(1,sizeof(cond_state_t));
		ASSERT(cnd);
		cnd->vc = (clck_t *)calloc(1,sizeof(clck_t)*THREAD_MAX);
		ASSERT(cnd->vc);
		cond_state_map[cond_addr] = cnd;
	}

	vc_copy(cnd->vc, thrd->vc);

	vc_inc(thrd->vc,tid);
	VC_DEBUG(tid,"INC  thrd",thrd->vc);

}

void ft_before_wait(void *__cond_addr, void *__lock_addr, tid_t _tid)
{

	tid_t tid = _tid;
	address_t cond_addr = (address_t)(uintptr_t)__cond_addr;
	address_t lock_addr = (address_t)(uintptr_t)__lock_addr;
	ASSERT(0<=tid && tid < THREAD_MAX);
	//ASSERT(UNIT_DOWN_ALIGN(cond_addr, WORD_SIZE) == cond_addr);
	//ASSERT(UNIT_DOWN_ALIGN(lock_addr, WORD_SIZE) == lock_addr);

	DPRINT("[%d] b_wait(cond_addr:0x%lx,lock_addr:0x%lx)\n",tid,cond_addr,lock_addr);

	thread_state_t *thrd = thread_state_get(tid);
	ASSERT(thrd);

	// UNLOCK
	lock_state_t *lck = lock_state_get(lock_addr);
	if(lck==NULL){
		lck = (lock_state_t *)calloc(1,sizeof(lock_state_t));
		ASSERT(lck);
		lck->vc = (clck_t *)calloc(1,sizeof(clck_t)*THREAD_MAX);
		ASSERT(lck->vc);
		lock_state_map[lock_addr] = lck;
	}

	vc_copy(lck->vc, thrd->vc);

	vc_inc(thrd->vc, tid);
	VC_DEBUG(tid,"thrd",thrd->vc);

	//nop
	asm("nop");

}

void ft_after_wait(void *__cond_addr, void *__lock_addr, tid_t _tid)
{

	tid_t tid = _tid;
	address_t cond_addr = (address_t)(uintptr_t)__cond_addr;
	address_t lock_addr = (address_t)(uintptr_t)__lock_addr;
	ASSERT(0<=tid && tid < THREAD_MAX);
	//ASSERT(UNIT_DOWN_ALIGN(cond_addr, WORD_SIZE) == cond_addr);
	//ASSERT(UNIT_DOWN_ALIGN(lock_addr, WORD_SIZE) == lock_addr);

	DPRINT("[%d] a_wait(lock_addr:0x%lx)\n",tid,lock_addr);

	thread_state_t *thrd = thread_state_get(tid);
	ASSERT(thrd);

	// WAIT

	cond_state_t *cnd = cond_state_get(cond_addr);
	if(cnd==NULL){
		cnd = (cond_state_t *)calloc(1,sizeof(cond_state_t));
		ASSERT(cnd);
		cnd->vc = (clck_t *)calloc(1,sizeof(clck_t)*THREAD_MAX);
		ASSERT(cnd->vc);
		cond_state_map[cond_addr] = cnd;
	}

	VC_DEBUG(tid,"thrd",thrd->vc);
	vc_join(thrd->vc, cnd->vc);
	VC_DEBUG(tid,"thrd",thrd->vc);

	// LOCK

	lock_state_t *lck = lock_state_get(lock_addr);
	if(lck==NULL){
		lck = (lock_state_t *)calloc(1,sizeof(lock_state_t));
		ASSERT(lck);
		lck->vc = (clck_t *)calloc(1,sizeof(clck_t)*THREAD_MAX);
		ASSERT(lck->vc);
		lock_state_map[lock_addr] = lck;
	}

	VC_DEBUG(tid,"thrd",thrd->vc);
	vc_join(thrd->vc, lck->vc);
	VC_DEBUG(tid,"thrd",thrd->vc);

}

/****************************************************************************************
 * READ and WRITE checks
 ***************************************************************************************/

static void __ft_read(address_t addr, void* rip, tid_t _tid)
{
	tid_t tid = _tid;
	ASSERT(0<=tid && tid < THREAD_MAX);
	ASSERT(UNIT_DOWN_ALIGN(addr, DETECTION_UNIT_SIZE) == addr);

	DPRINT("[%d] read(addr:0x%lx)\n",tid,addr);

	thread_state_t *thrd = thread_state_get(tid);
	ASSERT(thrd);

	var_state_t *var = var_state_get(addr);
	if(var==NULL){
		//printf("||Rtid=%d||var=NULL\n",	tid);
		var = (var_state_t *)calloc(1,sizeof(var_state_t));
		ASSERT(var);
		var->R.clck = thrd->vc[tid].clck;
		var->R.tid = tid;
		var->rip = rip;
		//NOTE: we initialize Rvc when needed
		var_state_map[addr] = var;
	}
	else{
		// same epoch
		if((var->R.tid == tid)&&(var->R.clck == thrd->vc[tid].clck)){
			return;
		}

		// write-read race?
		if(var->W.clck > thrd->vc[var->W.tid].clck)
		{
			race_db.insert(std::make_tuple(var->rip,rip,RACE_TYPE_RAW));

			DPRINT("[DATA RACE] [%d]W(%p)-[%d]R(%p) : var->W.clck=%d > thrd->vc[%d].clck=%d\n",
					var->W.tid, var->rip, tid, rip, var->W.clck, var->W.tid, thrd->vc[var->W.tid].clck);
		}

		// update read state
		if(var->R.clck == READ_SHARED) {            // shared
			var->Rvc[tid].clck = thrd->vc[tid].clck;
			var->Rvc[tid].tid=tid;
		} else {
			if(var->R.clck <= thrd->vc[var->R.tid].clck){   // exclusive
				var->R.clck = thrd->vc[tid].clck;
				var->R.tid = tid;
			}else{                              // (slow path)
				if(var->Rvc==NULL){
					var->Rvc = (clck_t *)calloc(1,sizeof(clck_t)*THREAD_MAX);
					ASSERT(var->Rvc);
				}
				var->Rvc[var->R.tid].clck = var->R.clck;
				//var->Rvc[var->R.tid].tid = tid;
				var->Rvc[tid].clck = thrd->vc[tid].clck;
				var->Rvc[tid].tid = tid;
				var->R.clck = READ_SHARED;
			}
		}
		var->rip = rip;
	}
}

static void __ft_write(address_t addr, void* rip, tid_t _tid)
{

	tid_t tid = _tid;
	ASSERT(0<=tid && tid < THREAD_MAX);
	ASSERT(UNIT_DOWN_ALIGN(addr, DETECTION_UNIT_SIZE) == addr);

	DPRINT("[%d] write(addr:0x%lx)\n",tid,addr);

	thread_state_t *thrd = thread_state_get(tid);
	ASSERT(thrd);

	var_state_t *var = var_state_get(addr);
	if(var==NULL){
		//printf("||Wtid=%d||var=NULL\n",	tid);
		var = (var_state_t *)calloc(1,sizeof(var_state_t));
		ASSERT(var);
		var->W.clck = thrd->vc[tid].clck; // thrd->epoch
		var->W.tid = tid;
		var->rip = rip;
		var_state_map[addr] = var;
	}
	else{

		// same epoch
		if((var->W.tid==tid)&&(var->W.clck == thrd->vc[tid].clck)){
			return;
		}

		// write-write race?
		if(var->W.clck > thrd->vc[var->W.tid].clck)
		{
			race_db.insert(std::make_tuple(var->rip,rip,RACE_TYPE_WAW));

			DPRINT("[DATA RACE] [%d]W(%p)-[%d]W(%p) : var->W.clck=%d > thrd->vc[%d].clck=%d\n",
					var->W.tid, var->rip, tid, rip, var->W.clck, var->W.tid, thrd->vc[var->W.tid].clck);
		}

		// read-write race?
		if(var->R.clck != READ_SHARED) {
			if (var->R.clck > thrd->vc[var->R.tid].clck){
				race_db.insert(std::make_tuple(var->rip,rip,RACE_TYPE_WAR1));

				DPRINT("[DATA RACE] [%d]R(%p)-[%d]W(%p) : var->R.clck=%d > thrd->vc[%d].clck=%d\n",
						var->R.tid, var->rip, tid, rip, var->R.clck, var->R.tid, thrd->vc[var->R.tid].clck);
			}
		}else{
			ASSERT(var->Rvc);
			if (!vc_is_ordered(tid, var->Rvc,thrd->vc)){  // (slow path)
				race_db.insert(std::make_tuple(var->rip,rip,RACE_TYPE_WAR2));

				DPRINT("[DATA RACE] [%d]R(%p)-[%d]W(%p) : var->Rvc NOT ORDERED thrd->vc\n",
						var->R.tid, var->rip, tid, rip);
			}
		}

		// update write state
		var->W.clck = thrd->vc[tid].clck; // thrd->epoch
		var->W.tid = tid;
		var->rip = rip;
	}
}


void ft_read(void *__addr, int size, void* rip, tid_t tid)
{
	address_t addr = (address_t)(uintptr_t)__addr;
	address_t start_addr = UNIT_DOWN_ALIGN(addr, DETECTION_UNIT_SIZE);
	address_t end_addr = UNIT_UP_ALIGN(addr + size, DETECTION_UNIT_SIZE);
	for (address_t iaddr = start_addr; iaddr < end_addr; iaddr += DETECTION_UNIT_SIZE)
	{
		__ft_read(iaddr, rip, tid);
	}
}

void ft_write(void *__addr, int size, void* rip, tid_t tid)
{
	address_t addr = (address_t)(uintptr_t)__addr;
	address_t start_addr = UNIT_DOWN_ALIGN(addr, DETECTION_UNIT_SIZE);
	address_t end_addr = UNIT_UP_ALIGN(addr + size, DETECTION_UNIT_SIZE);
	for (address_t iaddr = start_addr; iaddr < end_addr; iaddr += DETECTION_UNIT_SIZE)
	{
		__ft_write(iaddr, rip, tid);
	}
}

