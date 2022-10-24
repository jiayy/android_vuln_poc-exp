#define _GNU_SOURCE	1
#include <sched.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>

#include "helpers.h"
#include "log.h"


/*
 * Attach to a specific CPU.
 */
bool pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);

	if (sched_setaffinity(0, sizeof(set), &set) < 0) {
		log_err("sched_setafinnity(): %s\n", strerror(errno));
		return false;
	} 

	return true;
}
