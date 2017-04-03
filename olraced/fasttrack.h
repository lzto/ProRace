/*
 * fasttrack race detector
 * forked from txgo
 * Nov 2015 Tong Zhang<ztong@vt.edu>
 */
#ifndef __fasttrack_h__
#define __fasttrack_h__

typedef int tid_t;

#ifdef __cplusplus
extern "C" {
#endif

	/****************************************************************************************
	 * INIT 
	 ***************************************************************************************/

	void ft_init();
	void ft_fini();

	/****************************************************************************************
	 * MALLOC/FREE
	 ***************************************************************************************/

	void ft_mem_alloc(void *__addr, unsigned long size);
	void ft_mem_free(void *__addr);

	/****************************************************************************************
	 * UNLOCK -> LOCK
	 ***************************************************************************************/

	void ft_before_unlock(void *__lock_addr, tid_t _tid);
	void ft_after_lock(void *__lock_addr, tid_t _tid);

	/****************************************************************************************
	 * THREAD_CREATE -> THREAD_INIT
	 ***************************************************************************************/

	void ft_after_thread_create(unsigned long child_pthread_id, tid_t _tid);
	void ft_after_thread_init(tid_t _tid);

	/****************************************************************************************
	 * THREAD_EXIT -> THREAD_JOIN
	 ***************************************************************************************/

	void ft_before_thread_exit(tid_t _tid);
	void ft_after_thread_join(unsigned long child_pthread_id, tid_t _tid);

	/****************************************************************************************
	 * SIGNAL -> WAIT
	 ***************************************************************************************/

	void ft_before_signal(void *__cond_addr, tid_t _tid);
	void ft_before_broadcast(void *__cond_addr, tid_t _tid);
	void ft_before_wait(void *__cond_addr, void *__lock_addr, tid_t _tid);
	void ft_after_wait(void *__cond_addr, void *__lock_addr, tid_t _tid);

	/****************************************************************************************
	 * READ and WRITE checks
	 ***************************************************************************************/

	void ft_read(void *__addr, int size, void* rip, tid_t _tid);
	void ft_write(void *__addr, int size, void* rip, tid_t _tid);

#ifdef __cplusplus
}
#endif

#endif//__fasttrack_h__

