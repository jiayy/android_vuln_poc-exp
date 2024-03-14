# Mali GPU Kernel LPE

This article provides an in-depth analysis of two kernel vulnerabilities within the Mali GPU, reachable from the default application sandbox, which I independently identified and reported to Google. It includes a kernel exploit that achieves arbitrary kernel r/w capabilities. Consequently, it disables SELinux and elevates privileges to root on Google Pixel 7 and 8 Pro models running the following Android 14 versions:
- Pixel 8 Pro: `google/husky/husky:14/UD1A.231105.004/11010374:user/release-keys`
- Pixel 7 Pro: `google/cheetah/cheetah:14/UP1A.231105.003/11010452:user/release-keys`
- Pixel 7 Pro: `google/cheetah/cheetah:14/UP1A.231005.007/10754064:user/release-keys`

## Vulnerabilities
This exploit leverages two vulnerabilities: an integer overflow resulting from an incomplete patch in the `gpu_pixel_handle_buffer_liveness_update_ioctl` ioctl command, and an information leak within the timeline stream message buffers.

### Buffer Underflow in gpu_pixel_handle_buffer_liveness_update_ioctl() Due to Incorrect Integer Overflow Fix
Google addressed an integer overflow in the `gpu_pixel_handle_buffer_liveness_update_ioctl` ioctl command [in this commit](https://android.googlesource.com/kernel/google-modules/gpu/+/68073dce197709c025a520359b66ed12c5430914%5E%21/#F0). At first, when I reported this issue, I thought the bug was caused by an issue in the patch described earlier. After reviewing the report, I came to the realization that my analysis of the a vulnerability was inaccurate. Despite my first assumption of the patch being incomplete, it effectively resolves and prevents an underflow in the calculation. This lead me to suspect that the change wasn't applied in the production builds. However, although I can cause an underflow in the calculation, it is not possible to cause an overflow. This suggests that the ioctl command has been partially fixed, although not with the above patch shown above. Looking at IDA revealed that another incomplete patch was shipped in the production releases, and this patch is not present in any git branch of the mali gpu kernel module.
 
This vulnerability was first discovered in the latest Android version and reported on November 19, 2023. Google later informed me that they had already internally identified it and had assigned it [CVE-2023-48409](https://source.android.com/docs/security/bulletin/pixel/2023-12-01) in the December Android Security Bulletin, labeling it as a duplicate issue. 
Although I was able to verify that the bug had been internally identified months prior to my report, (based on the commit date around August 30) there remains confusion. Specifically, it's strange that the Security Patch Levels (SPL) for October and November of the most recent devices were still affected by this vulnerability —I haven't investigated versions prior to these. Therefore, I am unable to conclusively determine whether this was truly a duplicate issue and if the appropriate patch was indeed scheduled for December prior to my submission or if there was an oversight in addressing this vulnerability.

Anyway, what makes this bug powerful is the following:
- The buffer `info.live_ranges` is fully user-controlled.
- The overflowing values are user-controlled input, thereby, we can overflow the calculation so the `info.live_ranges` pointer can be at an arbitrary offset prior to the start of the `buff` kernel address.
- The allocation size is also user controlled input, which gives the ability to request a memory allocation from any general-purpose slab allocator.

This vulnerability shares similarities with the [DeCxt::RasterizeScaleBiasData() Buffer underflow vulnerability](https://github.com/0x36/weightBufs) I found and exploited in the iOS 15 kernel back in 2022.

### Leakage of Kernel Pointers in Timeline Stream Message Buffers
The GPU Mali implements a custom `timeline stream` designed to gather information, serialize it, and subsequently write it to a ring buffer following a specific format. Users can invoke the ioctl command `kbase_api_tlstream_acquire` to obtain a file descriptor, enabling them to read from this ring buffer. The format of the messages is as follows:
- A [packet header](https://android.googlesource.com/kernel/google-modules/gpu/+/refs/heads/android-gs-pantah-5.10-android14-qpr2-beta/mali_kbase/mali_kbase_mipe_proto.h#68)
- A [message id](https://android.googlesource.com/kernel/google-modules/gpu/+/refs/heads/android-gs-pantah-5.10-android14-qpr2-beta/mali_kbase/tl/mali_kbase_tracepoints.c#34)
- A serialized message buffer, where the specific content is contingent upon the message ID.
For example, the `__kbase_tlstream_tl_kbase_kcpuqueue_enqueue_fence_wait` function serializes the `kbase_kcpu_command_queue` and `dma_fence` kernel pointers into the message buffer, resulting in leaking kernel pointers to user space process.
```c
void __kbase_tlstream_tl_kbase_kcpuqueue_enqueue_fence_wait(
	struct kbase_tlstream *stream,
	const void *kcpu_queue,
	const void *fence
)
{
	const u32 msg_id = KBASE_TL_KBASE_KCPUQUEUE_ENQUEUE_FENCE_WAIT;
	const size_t msg_size = sizeof(msg_id) + sizeof(u64)
		+ sizeof(kcpu_queue)
		+ sizeof(fence)
		;
	char *buffer;
	unsigned long acq_flags;
	size_t pos = 0;

	buffer = kbase_tlstream_msgbuf_acquire(stream, msg_size, &acq_flags);

	pos = kbasep_serialize_bytes(buffer, pos, &msg_id, sizeof(msg_id));
	pos = kbasep_serialize_timestamp(buffer, pos);
	pos = kbasep_serialize_bytes(buffer,
		pos, &kcpu_queue, sizeof(kcpu_queue));
	pos = kbasep_serialize_bytes(buffer,
		pos, &fence, sizeof(fence));

	kbase_tlstream_msgbuf_release(stream, acq_flags);
}
```
The proof of concept exploit leaks the `kbase_kcpu_command_queue` object address by monitoring to the message id `KBASE_TL_KBASE_NEW_KCPUQUEUE` which is dispatched by the `kbasep_kcpu_queue_new` function whenever a new kcpu queue object is allocated.

Google informed me that the vulnerability was reported in March 2023 and was assigned  [CVE-2023-26083](https://source.android.com/docs/security/bulletin/2023-07-01) in their security bulletin. Nonetheless, I was able to replicate the issue on the latest Pixel devices shipped with the Security Patch Levels (SPL) for October and November, indicating that the fix had not been applied correctly or at all. Subsequently, Google quickly addressed the issue in the December Security Update Bulletin without offering credit, and later informed me that the issue was considered a duplicate. The rationale behind labeling this issue as a duplicate, however, remains questionable.

## Exploitation
---
So I have two interesting vulnerabilities. The first one offers a powerful capability to modify the content of any 16-byte aligned kernel address that comes before the allocated ~buff~ address. The second vulnerability provides hints into the potential locations of objects within the kernel memory.

### Notes on buffer_count and live_ranges_count Values
With total control over the `buffer_count` and `live_ranges_count` fields, I have the flexibility to select the target slab and the precise offset I intend to write to. However, selecting values for `buffer_count` and `live_ranges_count` requires careful consideration due to several constraints and factors:
- Both values are related, and the overflow will occur only if all the newly introduced checks are bypassed.
- The requirement for the negative offset to be 16-bytes aligned restricts the ability to write to any chosen location. However, this is generally not a significant hindrance.
- Opting for a larger offset leads to a large amount of data being written to areas of memory that may not be intended targets. For instance, if the allocation size overflows to `0x3004`, the `live_ranges` pointer would be set to `-0x4000` bytes from the `buff` object's allocated space. The `copy_from_user` function would then write `0x7004` bytes, based on the calculation of `update->live_ranges_count` times 4. Consequently, this operation would result in user-controlled data overwriting the memory area between the `live_ranges` pointer and the `buff` allocation. It is essential, therefore, to carefully ensure that no critical system objects within that range are accidentally overwritten. Given that the operation involves a `copy_from_user` call, one might consider triggering an `EFAULT` by deliberately un-mapping the undesired memory region following the user source buffer to prevent data from being written to sensitive locations. However, this approach is ineffective, that's because if the `raw_copy_from_user` function fails, it will zero out the remaining bytes in the destination kernel buffer. This behavior is implemented to ensure that in case of a partial copy due to an error, the rest of the kernel buffer does not contain uninitialized data.

```c
static inline __must_check unsigned long
_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	unsigned long res = n;
	might_fault();
	if (!should_fail_usercopy() && likely(access_ok(from, n))) {
		instrument_copy_from_user(to, from, n);
		res = raw_copy_from_user(to, from, n);
	}
	if (unlikely(res))
		memset(to + (n - res), 0, res);
	return res;
}
```

Considering this, we need to carefully select the object to overwrite and the data to write.

### Choosing the Right Object to Overwrite
Because I’m stuck with this unfortunate check, my strategy is to identify an object that, if nulled out, will not produce any undesired outcome. But, before I get to that, there's another issue to deal with. Remember when I said in the last part that I can choose any allocation size and thus any general purpose slab cache allocator to service my allocation buffer? That’s not correct, because it is because of `copy_from_user` again! It is due to the [CONFIG_HARDENED_USERCOPY](https://lwn.net/Articles/693745/) mitigation. It forbids specifying a size that does not meet the corresponding slab cache size where the kernel destination buffer corresponds (in this case) of a heap object. It determines whether the buffer's page is a slab page, and if so, it retrieves the matching `kmem_cache->size` and determines whether the user supplied size will not exceed it; otherwise, the kernel just crashes due to the size mismatch. So, in other words, I cannot target objects that belong to the general purpose allocator, BUT I can still target objects that have large sizes (i.e. those served directly by the page allocator).

The first thought that came to mind was to use the `pipe_buffer` technique, which is a very elegant technique to obtain arbitrary read/write primitives. I won't go into detail about the technique, but readers are encouraged to read this fantastic blog from [Interrupt Labs](https://www.interruptlabs.co.uk/articles/pipe-buffer). When constructing a pipe object, the `pipe_buffer` object is initially created in an array of 16 elements; however, the array size can be adjusted using `fcntl(F_SETPIPE_SZ)`. Therefore, the `pipe_buffer` array allocation can be adjusted such that it can be served from the page allocator, making it a perfect target object to attack.
After selecting the pipe_buffer object as a target candidate, the next step toward achieving kernel r/w is to overwrite its content with the underflow vulnerability, which will allow me to read/write from/to any memory location whose page is overwriting the `pipe_buffer->page` field. 
Because the vulnerability allows me to write arbitrary data, I can control the whole content of '`pipe_buffer`,' including its page field, and to do so, I need to allocate the `pipe_buffer` array before the vulnerable `kbuff` object and they have to be next to each other.

### Positioning pipe_buffer and buff Objects Adjacently
I sprayed the kernel memory with a lot of `kbase_kcpu_command_queue` objects then followed by a bunch of `pipe_buffer` arrays.
I can’t just use the `pipe_buffer` arrays alone as a primary source for spraying due to the limitation imposed by `pipe_max_size`. Therefore, I decided to start spraying with the `kbase_kcpu_command_queue` object. Choosing the `kbase_kcpu_command_queue` object was for two reasons: its allocation size is `0x38C8` thus handled by the page allocator, and I can deterministically obtain its kernel address using the information kernel leak bug, making it a good object to spray with as well as a good object to target (as we’ll see in the next section).

As mentioned before, I used `fcntl(F_SETPIPE_SZ)` to increase the size of the `pipe_buffer` array allocation so that it can be served by the page allocator. To be more specific, I chose the allocation size to be a  ==0x4000 bytes (4 * PAGE_SIZE)== in order to be consistent with the `kbase_kcpu_command_queue` allocations.

### Obtaining a struct page Address
In order to properly use the `pipe_buffer`, a page address is required. Being able to identify the kernel address of a `kbase_kcpu_command_queue` object that I can deliberately create and destroy makes it a good candidate to use and finding its matching `struct page` can be achieved by using the `virt_to_page` .

### Contents to Write in the pipe_buffer  
So the `pipe_buffer` object is as follow:
```c
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
```
As previously mentioned, the `page` field must include a valid page address. The `offset` and `len` fields must not exceed `PAGE_SIZE`, otherwise the pipe will increase the head/tail counters, resulting in the use of a new `pipe_buffer` object and loss of control over the fake pipe buffer. 
Also, the `flags` must be `PIPE_BUF_FLAG_CAN_MERGE` so the following `pipe_write` calls instead of blindly incrementing the head counter and using the next pipe buffer, it first checks whether there’s a space in the current `pipe_buffer` that will fit the write request or not, and if there is, it will simply append data to the same pipe buffer starting from the value stored at the `len` field. 
In order to avoid crashing the device at `pipe_buf_confirm`, which is called by `pipe_write` and `pipe_read`’, the `ops` pointer must also be a valid kernel address with a `ops->confirm` field set to _NULL_. I can simply use an offset within the leaked `kbase_kcpu_command_queue` object that is NULL and will not change under any circumstances.

### Choosing the Optimal Offset Value for Underflow
While the allocation sizes of the `buff` ,`kbase_kcpu_command_queue` and `pipe_buffer` are ~0x4000~ bytes, I chose to underflow the buffer with **0x8000** bytes. why ? 

Let's take a brief look at how `pipe_buffers` are updated during read and write operations. Assume we can shape the `pipe_buffer` to look like this:

```c
struct pipe_buffer {
	.page = virt_to_page(addr),
	.offset =  0,
	.len = 0x40,
	.ops = kcpu_addr + 0x50,
	.flags = PIPE_BUF_FLAG_CAN_MERGE,
	unsigned long private = 0
};
```

While the bug gives the ability to arbitrary control this content of this object, it only does so **once** because the underflowed object is freed immediately after the `ioctl` call finishes. This actually poses a problem because I need to manually update the `pipe_buffer` object to make it useable again since each pipe read/write operation:
- The `.page` field is not updated; it remains the same, and when the buffer is empty, it is released, which I do not want to happen because the `.ops` field is not correctly set. 
- Because the `pipe_buffer` updates the `.offset` field on a read operation, therefore, I cannot read the same memory region again. 
- The data written to the `pipe_buffer` will be appended to the buffer starting from the `.len` value (assuming that `PIPE_BUF_FLAG_CAN_MERGE` flag is set) and the `.len` is updated accordingly. That is, we can't write data into the exact address twice. 

As a result, unless I properly update the `pipe_buffer` after each read or write operation, I cannot read and write from/to the same pipe at the same time. That's why underflowing with `0x8000` bytes is much more practical, because instead of overwriting a single `pipe_buffer`, **I'll overwrite two distinct pipe_buffer instances of two distinct pipes objects: one for will be considered for read and the other for write operations**.

```c
#define PIPE_BUF_FLAG_CAN_MERGE	0x10	/* can merge buffers */

pipe_read = (struct pipe_buffer *)( ptr);
pipe_read->page = virt_to_page(ta->kcpu_kaddr);
pipe_read->offset = 0;
pipe_read->len = 0xfff;
pipe_read->ops = (const void *)(ta->kcpu_kaddr + 0x50);
pipe_read->flags = PIPE_BUF_FLAG_CAN_MERGE;
pipe_read->private = 0;

pipe_write = (struct pipe_buffer *)( ptr + 0x4000);
pipe_write->page = virt_to_page(ta->kcpu_kaddr);
pipe_write->offset = 0;
pipe_write->len = 0;             /* This is the starting position of the pipe_write */
pipe_write->ops = (const void *)(ta->kcpu_kaddr + 0x50);
pipe_write->flags = PIPE_BUF_FLAG_CAN_MERGE;
pipe_write->private = 0;
```

The `pipe_read` is a fake pipe buffer that will be used for reading data from the target page starting at `.offset = 0` up to `0xfff` bytes, whereas `pipe_write` is a fake `pipe_buffer` that will be used for writing data starting from `.len = 0` up to `0xfff` bytes. 
It's also very important to mention again that writing more than `PAGE_SIZE` bytes will push the pipe to increment the head counter, therefore using a fresh newly allocated `pipe_buffer` and losing control over our fake `pipe_write`. In the other hand, emptying (reading 0xfff data from) `fake_read` buffer tells the kernel to release the actual page by calling `ops→release` causing the kernel to crash because I still don’t have a kernel text address. 
Although I managed to segregate the pipe read and write operations so that performing a write in one pipe end will not interfere with the other pipe buffer and vice versa, I still haven’t solved the core issue: How to reliably update the pipe buffer? The obvious answer came to mind was just to repeat the spray process again and again after each pipe read or write call.  And this makes no sense because it would have had a significant impact on exploit reliability. In the following section, I will divide the goal into two sub-goals: to begin, I'll focus on the `.page` field only, followed by the `.len/.offset` fields afterward. 

### Modifying the pipe_buffer→page Field
To my surprise, I don't have or need to update the `.page` at all, that's because I can overwrite the `pipe_buffer→page`  to point to the page address of the leaked `kbase_kcpu_command_queue`.  Therefore, **All I need to do is release the `kbase_kcpu_command_queue` object and overlap it with a new `pipe_buffer` object. Yup! Now I have a `pipe_buffer→page` that points to a legitimate `pipe_buffer` object!
Replacing `kbase_kcpu_command_queue` with `pipe_buffer` gives us the ability to manipulate a legitimate pipe buffer without regularly having to update the `.page` field. However, I still have to deal with the `.len` and `.offset` fields.

### Modifying the pipe_buffer→len/offset Fields
As I've mentioned earlier, doing pipe read/write updates the `.len` and `.offset` fields, rendering subsequent read/write operations on the same page unusable, even if performed over the two distinct pipes. Here's another trick: **there's a technique to read/write data without even touching the `.len/.offset` fields!**.  And it is possible to achieve this by faulting `copy_page_from_iter` and `copy_page_to_iter` calls on `pipe_read/write`! Yes, just like `copy_to/from_user`, `copy_page_to/from_iter` copies data from/to user-space that is passed through the `iov_iter` structure, and it can be faulted. 

To continue with the previous example, if we wish to write 8 bytes of data to an address, the provided user space buffer size must be 8, followed by an unmapped or non-readable area of memory, and then pass `9` as a size argument to the `write` system call, indicating the amount of data that we want to write.This operation will write 8 bytes and fail on the _ninth_ because it encounters an unmapped/unread memory location. As a result, the data has been effectively written to the destination kernel buffer and the`.len` field has not been modified. The `pipe_write` kernel function will just return without updating the `buf->len` field.

```c
		if ((buf->flags & PIPE_BUF_FLAG_CAN_MERGE) &&
		    offset + chars <= PAGE_SIZE) {
			ret = pipe_buf_confirm(pipe, buf);
			if (ret)
				goto out;

			ret = copy_page_from_iter(buf->page, offset, chars, from);
			if (unlikely(ret < chars)) {
				ret = -EFAULT;
				goto out;
			}

			buf->len += ret;
			if (!iov_iter_count(from))
				goto out;
		}
```
The same is true for read operations; if we wish to read 8 bytes, make the ninth byte of the buffer unreadable then just claim that we want to read 9 bytes, the data will be copied to the user buffer without changing the `.offset` field. 
As a result, we are able to perform unlimited read/write operations on any kernel memory address without having to recurrently go through the spray process.

### Getting root
Now that I have a strong arbitrary read/write primitive, I just looked through all the `struct page` in the `VMEMMAP_START` array to determine the kernel text starting address using the technique outlined in the [Interrupt Labs](https://www.interruptlabs.co.uk/articles/pipe-buffer) blog post. Then I realized that `init_task` is nulled out in _Android November Security Updates_, so I just used `kthreadd_task` instead. Having `kthreadd_task` kernel address allowed me to walk the `task->tasks` list and obtain my own `current` task kernel address, then zero out the `cred` structure to achieve root privileges.

Later, I realized scanning all the page addresses was unnecessary because I already had the anon_pipe_buf_ops kernel text address from a pipe_buffer object. With this information, I could deduce the kernel text base address, effectively bypassing KASLR.

### Disable SELinux
The exploit disables SELinux also, with the kernel text base address, I just need to find the `selinux_state` global structure location and then zero out the `.enforcing` value.

## Proof of Concept
The proof of concept accompanying the report was tested on Pixel 7 and 8 Pro devices running Android 14 with the October and November ASBs, achieving a success rate of nearly 100%.
It's also important to mention that the exploit will not work out of the box in other devices due to the use of some hardcoded offsets. In order to add support for a new device, one must have to provide the following:
- `kthreadd_task` offset from the kernel base address.
- `selinux_state` offset from the kernel base address.
- `task_struct->cred` , `task_struct->pid` and `task_struct->tasks` structure offsets.
- `anon_pipe_buf_ops` offset from the kernel base address.

### Compilation 
To compile the exploit as a standalone binary use the following command, then use `adb shell` to run it:
```sh
$ aarch64-linux-androidXX-clang++ -static-libstdc++ -w -Wno-c++11-narrowing -DUSE_STANDALONE -o poc poc.cpp -llog
$ adb push poc /data/local/tmp/
$ adb shell /data/local/tmp/poc
```
You can also run the exploit via an Android Studio App by embeding this directory with it and make sure to disable the useless C++ warnings by adding `-w -Wno-c++11-narrowing` to the cmake file.

### Demo
```shell
$ adb logcat  |grep -i EXPLOIT
11-28 16:04:12.500  7989  7989 E EXPLOIT : [+] Target device: 'google/husky/husky:14/UD1A.231105.004/11010374:user/release-keys' 0xa9027bfdd10203ff 0xa90467faa9036ffc
11-28 16:04:15.563  7989  7989 E EXPLOIT : [+] Got the kcpu_id (0) kernel address = 0xffffff8901390000  from context (0x0)
11-28 16:04:18.441  7989  7989 E EXPLOIT : [+] Got the kcpu_id (255) kernel address = 0xffffff89b0bf8000  from context (0xff)
11-28 16:04:18.442  7989  7989 E EXPLOIT : [+] Found corrupted pipe with size 0xfff
11-28 16:04:18.442  7989  7989 E EXPLOIT : [+] SUCCESS! we have a fake pipe_buffer (0)!
11-28 16:04:18.444  7989  7989 E EXPLOIT : 10 00 39 01 89 FF FF FF  10 00 39 01 89 FF FF FF  | ..9.......9.....
11-28 16:04:18.444  7989  7989 E EXPLOIT : 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  | ................
11-28 16:04:18.444  7989  7989 E EXPLOIT : 00 B0 CD 12 C0 FF FF FF  00 00 00 00 00 00 00 00  | ................
11-28 16:04:18.444  7989  7989 E EXPLOIT : 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  | ................
11-28 16:04:18.445  7989  7989 E EXPLOIT : [+] Freeing kcpu_id = 0 (0xffffff8901390000)
11-28 16:04:18.446  7989  7989 E EXPLOIT : [+] Allocating 61 pipes with 256 slots
11-28 16:04:18.462  7989  7989 E EXPLOIT : [+] Successfully overlapped the kcpuqueue object with a pipe buffer
11-28 16:04:18.463  7989  7989 E EXPLOIT : 40 AB BA 26 FE FF FF FF  00 00 00 00 30 00 00 00  | @..&........0...
11-28 16:04:18.463  7989  7989 E EXPLOIT : 70 37 8D F1 DA FF FF FF  10 00 00 00 00 00 00 00  | p7..............
11-28 16:04:18.463  7989  7989 E EXPLOIT : 00 00 00 00 00 00 00 00                           | ........
11-28 16:04:18.463  7989  7989 E EXPLOIT : [+] pipe_buffer {.page = 0xfffffffe26baab40, .offset = 0x0, .len = 0x30, ops = 0xffffffdaf18d3770}
11-28 16:04:18.463  7989  7989 E EXPLOIT : [+] kernel base = 0xffffffdaf0010000, kthreadd_task = 0xffffff8002da3780 selinux_state = 0xffffffdaf28a3168
11-28 16:04:20.097  7989  7989 E EXPLOIT : [+] Found our own task struct 0xffffff88416c5c80
11-28 16:04:20.097  7989  7989 E EXPLOIT : [+] Successfully got root: getuid() = 0 getgid() = 0
11-28 16:04:20.097  7989  7989 E EXPLOIT : [+] Successfully disabled SELinux
11-28 16:04:20.102  7989  7989 E EXPLOIT : [+] Cleanup  ... OK
```

	