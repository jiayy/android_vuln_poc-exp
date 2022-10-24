#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <android/log.h>

#include "binder.h"
#include "binder_lookup.h"
#include "log.h"

#define HWSERVICE_MANAGER "android.hidl.manager@1.0::IServiceManager"
#define TOKEN_MANAGER   "android.hidl.token@1.0::ITokenManager"


typedef void * hidl_pointer;

struct hidl_handle {
   hidl_pointer phandle;
   bool owns_handle;
};

typedef struct hidl_string {
   hidl_pointer buffer;
   uint32_t size;
   bool owns_buffer;
} hidl_string;

typedef struct hidl_vec {
   hidl_pointer buffer;
   uint32_t size;
   bool owns_buffer;
} hidl_vec;

typedef struct service_list {
   struct service_list *next;
   const char *service_name;
   hidl_vec *token;
} service_list_t;

static service_list_t *services = NULL;


bool add_service_token(const char *service, hidl_vec *token)
{
   service_list_t *entry, *tmp;

   entry = calloc(1, sizeof(*entry));
   if (!entry)
      return false;

   /* Insert. */
   tmp = services;

   entry->service_name = strdup(service);
   entry->token = token;
   entry->next = tmp;

   if (!tmp) {
      services = entry;
   } else {
      entry->next = services;
      services = entry;
   }

   return true;
}

hidl_vec *get_service_token(const char *service)
{
   service_list_t *entry = services;

   while (entry) {
      if (!strcmp(entry->service_name, service))
         return entry->token;

      entry = entry->next;
   }

   return NULL;
}

/* Create wrapper for hidl_strings. */
hidl_string *hidl_string_new(const char *str)
{
   size_t len;
   hidl_string *hstr = calloc(1, sizeof(*hstr));
   if (!hstr)
      return NULL;

   len = strlen(str);

   hstr->buffer = (hidl_pointer)malloc(len + 1);
   if (!hstr->buffer) {
      free(hstr);
      return NULL;
   }

   strcpy(hstr->buffer, str);
   hstr->size = len;

   return hstr;
}

uint64_t find_hwservice(struct binder_state *bs, const char *service)
{
   uint8_t txn_data[0x1000];
   uint8_t reply_data[0x1000];
   uint8_t *ptr = txn_data;
   uint64_t offsets[0x10];
   uint64_t *offs = offsets;
   struct binder_write_read bwr;
   uint32_t buffers_size = 0;

   struct hidl_string *name;
   struct hidl_string *instance;
   uint64_t name_parent_off = 0;
   uint64_t instance_parent_off = 0;

   struct binder_buffer_object *bbo = NULL;

   struct {
      uint32_t cmd;
      struct binder_transaction_data txn;
      binder_size_t buffers_size;
   } __attribute__((packed)) writebuf;


   memset(txn_data, 0, 0x1000);
   bzero(&bwr, sizeof(bwr));


   name = hidl_string_new(service);
   instance = hidl_string_new("default");

   ptr = txn_data;

   /* Write the interface token first, as a classic C string, while taking
    * care of padding to 32bits.
    */
   memcpy(ptr, HWSERVICE_MANAGER, sizeof(HWSERVICE_MANAGER) + 1);
   ptr += sizeof(HWSERVICE_MANAGER) + 1;

   /* Align on 32bits. */
   while (((uint64_t)ptr) % sizeof(uint32_t))
      ptr++;

   /* write the hidl_string. */
   bbo = (struct binder_buffer_object *)ptr;
   bbo[0].hdr.type = BINDER_TYPE_PTR;
   bbo[0].buffer = name;
   bbo[0].length  = sizeof(struct hidl_string);
   bbo[0].flags = 0;
   bbo[0].parent = 0;
   bbo[0].parent_offset = 0;
   name_parent_off = (uint64_t)((uint8_t*)bbo - txn_data);
   buffers_size += bbo[0].length;
   *(offs++) = name_parent_off;

   ptr = &bbo[1];

   /* Embed the pointer. */
   bbo[1].hdr.type = BINDER_TYPE_PTR;
   bbo[1].buffer = name->buffer;
   bbo[1].length  = name->size + 1;
   bbo[1].flags = 1; //HAS_PARENT;
   //bbo[1].parent = name_parent_off;
   bbo[1].parent = 0;
   bbo[1].parent_offset = 0;
   buffers_size += bbo[1].length;
   *(offs++) = (uint64_t)((uint8_t*)&bbo[1] - txn_data);

   ptr = &bbo[2];

   bbo[2].hdr.type = BINDER_TYPE_PTR;
   bbo[2].buffer = instance;
   bbo[2].length = sizeof(struct hidl_string);
   bbo[2].flags = 0;
   instance_parent_off = (uint64_t)((uint8_t *)&bbo[2] - txn_data);
   *(offs++) = (uint64_t)((uint8_t*)&bbo[2] - txn_data);
   buffers_size += bbo[2].length;

   /* Embed the pointer. */
   bbo[3].hdr.type = BINDER_TYPE_PTR;
   bbo[3].buffer = instance->buffer;
   bbo[3].length  = instance->size + 1;
   bbo[3].flags = 1; //HAS_PARENT;
   //bbo[3].parent = instance_parent_off;
   bbo[3].parent = 2;
   bbo[3].parent_offset = 0;
   *(offs++) = (uint64_t)((uint8_t*)&bbo[3] - txn_data);
   buffers_size += bbo[3].length;

   ptr = &bbo[4];

   /* Send the BINDER_TRANSACTION_SG. */
   writebuf.cmd = BC_TRANSACTION_SG;
   writebuf.txn.target.handle = 0;
   writebuf.txn.code = 1;
   writebuf.txn.flags = 0;
   writebuf.txn.data_size = (uint64_t)ptr - (uint64_t)txn_data;
   writebuf.txn.offsets_size = (uint64_t)offs - (uint64_t)offsets;
   writebuf.txn.data.ptr.buffer = txn_data;
   writebuf.txn.data.ptr.offsets = offsets;

   /* Align buffers size. */
   while (buffers_size % 8)
      buffers_size++;
   writebuf.buffers_size = buffers_size;

   bwr.write_size = sizeof(writebuf);
   bwr.write_consumed = 0;
   bwr.write_buffer = &writebuf;
   bwr.read_size = 0;
   bwr.read_consumed = 0;
   bwr.read_buffer = 0;

   /* Send query. */
   ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
   uint32_t remaining, consumed;
   uint32_t rdata[32];
   remaining = 0, consumed = 0;

   while (binder_read_next(bs, rdata, &remaining, &consumed) != BR_REPLY);

   struct binder_transaction_data *tr = (struct binder_transaction *)((uint8_t*)rdata + consumed - sizeof(*tr));

   struct flat_binder_object *fbo = (struct flat_binder_object *)(tr->data.ptr.buffer + 4);

   /* Acquire the ref. */
   binder_acquire(bs, fbo->handle);

   /* Free the transaction. */
   binder_free_buffer(bs, tr->data.ptr.buffer);

   return fbo->handle;
}

hidl_vec * create_token(struct binder_state *bs, uint64_t tm_handle, uint64_t my_handle)
{
   uint8_t txn_data[0x1000];
   uint8_t reply_data[0x1000];
   uint8_t *ptr = txn_data;
   uint64_t offsets[0x10];
   uint64_t *offs = offsets;
   struct binder_write_read bwr;
   uint32_t buffers_size = 0;

   struct hidl_string *name;
   struct hidl_string *instance;
   uint64_t name_parent_off = 0;
   uint64_t instance_parent_off = 0;

   struct binder_buffer_object *bbo = NULL;

   struct {
      uint32_t cmd;
      struct binder_transaction_data txn;
      binder_size_t buffers_size;
   } __attribute__((packed)) writebuf;


   memset(txn_data, 0, 0x1000);
   bzero(&bwr, sizeof(bwr));


   ptr = txn_data;

   /* Write the interface token first, as a classic C string, while taking
    * care of padding to 32bits.
    */
   memcpy(ptr, TOKEN_MANAGER, sizeof(TOKEN_MANAGER) + 1);
   ptr += sizeof(TOKEN_MANAGER) + 1;

   /* Align on 32bits. */
   while (((uint64_t)ptr) % sizeof(uint32_t))
      ptr++;

   /* Add our strong binder. */
   struct flat_binder_object *fbo = (struct flat_binder_object *)ptr;
   fbo->hdr.type = BINDER_TYPE_BINDER;
   fbo->binder = my_handle;
   fbo->cookie = 0;
   *(offs++) = (uint64_t)fbo - (uint64_t)txn_data;
   
   ptr = &fbo[1];

   /* Send the BINDER_TRANSACTION_SG. */
   writebuf.cmd = BC_TRANSACTION_SG;
   writebuf.txn.target.handle = tm_handle;
   writebuf.txn.code = 1; //create_token
   writebuf.txn.flags = 0;
   writebuf.txn.data_size = (uint64_t)ptr - (uint64_t)txn_data;
   writebuf.txn.offsets_size = (uint64_t)offs - (uint64_t)offsets;
   writebuf.txn.data.ptr.buffer = txn_data;
   writebuf.txn.data.ptr.offsets = offsets;

   /* Align buffers size. */
   while (buffers_size % 8)
      buffers_size++;
   writebuf.buffers_size = buffers_size;

   bwr.write_size = sizeof(writebuf);
   bwr.write_consumed = 0;
   bwr.write_buffer = &writebuf;
   bwr.read_size = 0;
   bwr.read_consumed = 0;
   bwr.read_buffer = 0;

   /* Send query. */
   ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
   uint32_t remaining, consumed;
   uint32_t rdata[32];
   remaining = 0, consumed = 0;

   while (binder_read_next(bs, rdata, &remaining, &consumed) != BR_REPLY);

   struct binder_transaction_data *tr = (struct binder_transaction *)((uint8_t*)rdata + consumed - sizeof(*tr));

   /* Okay, build the HIDL vec. */
   bbo = (struct binder_buffer_object *)(tr->data.ptr.buffer + 4);
   hidl_vec *vec = calloc(1, sizeof(*vec));

   //Should check for BINDER_TYPE_PTR

   memcpy(vec, bbo->buffer, sizeof(*vec));

   /* Allocate the vec data. */
   void *data = malloc(vec->size);
   memcpy(data, vec->buffer, vec->size);

   /* replace the pointers. */
   vec->buffer = data;


   binder_free_buffer(bs, tr->data.ptr.buffer);

   /* return the token. */
   return vec;
}

uint32_t get_by_token(struct binder_state *bs, uint64_t tm, hidl_vec *token)
{
   uint8_t txn_data[0x1000];
   uint8_t reply_data[0x1000];
   uint8_t *ptr = txn_data;
   uint64_t offsets[0x10];
   uint64_t *offs = offsets;
   struct binder_write_read bwr;
   uint32_t buffers_size = 0;

   struct hidl_string *name;
   struct hidl_string *instance;
   uint64_t name_parent_off = 0;
   uint64_t instance_parent_off = 0;

   struct binder_buffer_object *bbo = NULL;

   struct {
      uint32_t cmd;
      struct binder_transaction_data txn;
      binder_size_t buffers_size;
   } __attribute__((packed)) writebuf;


   memset(txn_data, 0, 0x1000);
   bzero(&bwr, sizeof(bwr));


   ptr = txn_data;

   /* Write the interface token first, as a classic C string, while taking
    * care of padding to 32bits.
    */
   memcpy(ptr, TOKEN_MANAGER, sizeof(TOKEN_MANAGER) + 1);
   ptr += sizeof(TOKEN_MANAGER) + 1;

   /* Align on 32bits. */
   while (((uint64_t)ptr) % sizeof(uint32_t))
      ptr++;

   
   /* write the hidl_vec. */
   bbo = (struct binder_buffer_object *)ptr;
   bbo[0].hdr.type = BINDER_TYPE_PTR;
   bbo[0].buffer = token;
   bbo[0].length  = sizeof(*token);
   bbo[0].flags = 0;
   bbo[0].parent = 0;
   bbo[0].parent_offset = 0;
   name_parent_off = (uint64_t)((uint8_t*)bbo - txn_data);
   buffers_size += bbo[0].length;
   *(offs++) = name_parent_off;

   ptr = &bbo[1];

   /* Embed the pointer. */
   bbo[1].hdr.type = BINDER_TYPE_PTR;
   bbo[1].buffer = token->buffer;
   bbo[1].length  = token->size;
   bbo[1].flags = 1; //HAS_PARENT;
   //bbo[1].parent = name_parent_off;
   bbo[1].parent = 0;
   bbo[1].parent_offset = 0;
   buffers_size += bbo[1].length;
   *(offs++) = (uint64_t)((uint8_t*)&bbo[1] - txn_data);

   ptr = &bbo[2];


   /* Send the BINDER_TRANSACTION_SG. */
   writebuf.cmd = BC_TRANSACTION_SG;
   writebuf.txn.target.handle = tm;
   writebuf.txn.code = 3; //get_by_token
   writebuf.txn.flags = 0;
   writebuf.txn.data_size = (uint64_t)ptr - (uint64_t)txn_data;
   writebuf.txn.offsets_size = (uint64_t)offs - (uint64_t)offsets;
   writebuf.txn.data.ptr.buffer = txn_data;
   writebuf.txn.data.ptr.offsets = offsets;

   /* Align buffers size. */
   while (buffers_size % 8)
      buffers_size++;
   writebuf.buffers_size = buffers_size;

   bwr.write_size = sizeof(writebuf);
   bwr.write_consumed = 0;
   bwr.write_buffer = &writebuf;
   bwr.read_size = 0;
   bwr.read_consumed = 0;
   bwr.read_buffer = 0;

   /* Send query. */
   ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
   uint32_t remaining, consumed;
   uint32_t rdata[32];
   remaining = 0, consumed = 0;

   while (binder_read_next(bs, rdata, &remaining, &consumed) != BR_REPLY);

   struct binder_transaction_data *tr = (struct binder_transaction *)((uint8_t*)rdata + consumed - sizeof(*tr));

   struct flat_binder_object *fbo = (struct flat_binder_object *)(tr->data.ptr.buffer + 4);

   binder_acquire(bs, fbo->handle);

   return fbo->handle;
}

uint32_t grab_handle(struct binder_state *bs, char *name)
{

   uint64_t tm = find_hwservice(bs, TOKEN_MANAGER);

   hidl_vec *token = get_service_token(name);
   if (!token)
      return 0;

   uint32_t handle = get_by_token(bs, tm, token);

   binder_release(bs, tm);
   return handle;
}

int publish_handle(struct binder_state *bs, uint64_t handle, char *name)
{
   uint64_t tm = find_hwservice(bs, TOKEN_MANAGER);

   hidl_vec *vec = create_token(bs, tm, handle);
   if (!vec)
      return 0;

   /* Make the association. */
   add_service_token(name, vec);


   /* release the reference. */
   binder_release(bs, tm);

   return 1;
}

