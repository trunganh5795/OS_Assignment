#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t * q) {
	return (q->size == 0);
}

void enqueue(struct queue_t * q, struct pcb_t * proc) {
	/* add new pcb to queue [q] if queue is not full */
	if (q->size != MAX_QUEUE_SIZE)
		q->proc[q->size++] = proc;
}

struct pcb_t * dequeue(struct queue_t * q) {
	/* pop the pcb with highest prioprity from queue [q] */
	if (q->size == 0) return NULL;

	int temp = 0;
	for (int i = 1; i < q->size; i++) {
		if (q->proc[i]->priority > q->proc[temp]->priority) {
			temp = i;
		}
	}
	struct pcb_t * res = q->proc[temp];
	q->proc[temp] = q->proc[--q->size];

	return res;
}

