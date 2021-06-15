
#include "queue.h"
#include "sched.h"
#include <pthread.h>
#include <stdio.h>

#define LOG_SCHED 0

static struct queue_t ready_queue;
static struct queue_t run_queue;
static pthread_mutex_t queue_lock;

int queue_empty(void) {
	return (empty(&ready_queue) && empty(&run_queue));
}

/* print run queue and ready queue */
void printQueues(){
	printf("<<============= QUEUE =============>>\n");
	printf("A.READY QUEUE: \n");
	for(int i = 0; i < ready_queue.size; i++)
		printf("%d: pid: %d, prio: %d\n", i, ready_queue.proc[i]->pid, ready_queue.proc[i]->priority);
	
	printf("B.RUN QUEUE: \n");
	for(int i = 0; i < run_queue.size; i++)
		printf("%d: pid: %d, priority: %d\n", i, run_queue.proc[i]->pid, run_queue.proc[i]->priority);

	printf("<<============== END ==============>>\n");
}

void init_scheduler(void) {
	ready_queue.size = 0;
	run_queue.size = 0;
	pthread_mutex_init(&queue_lock, NULL);
}

struct pcb_t * get_proc(void) {
	struct pcb_t * proc = NULL;
	/*TODO: get a process from [ready_queue]. If ready queue
	 * is empty, push all processes in [run_queue] back to
	 * [ready_queue] and return the highest priority one.
	 * Remember to use lock to protect the queue.
	 * */
	pthread_mutex_lock(&queue_lock);
	if (empty(&ready_queue))
		while(!empty(&run_queue))
			ready_queue.proc[ready_queue.size++] = run_queue.proc[--run_queue.size];

	if (!empty(&ready_queue))
		proc = dequeue(&ready_queue);
	pthread_mutex_unlock(&queue_lock);
	
	return proc;
}

void put_proc(struct pcb_t * proc) {
	pthread_mutex_lock(&queue_lock);
	enqueue(&run_queue, proc);
	pthread_mutex_unlock(&queue_lock);

	if(LOG_SCHED) printQueues();
}

void add_proc(struct pcb_t * proc) {
	pthread_mutex_lock(&queue_lock);
	enqueue(&ready_queue, proc);
	pthread_mutex_unlock(&queue_lock);

	if(LOG_SCHED) printQueues();
}



