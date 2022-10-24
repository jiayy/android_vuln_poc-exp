#ifndef REALLOC_H_
#define REALLOC_H_

#define NREALLOC 0x80 * 8
#define BUFSZ	0x80

void *realloc_thread(void *args);
void spawn_realloc_threads();
void cleanup_realloc_threads();
void setup_realloc_buffer(void *content, size_t size);
bool discard_realloc_thread(pid_t pid);


#endif /*! REALLOC_H_ */
