#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "err_state.h"

#define SOL_TLS		(282)

/* TLS socket options */
#define TCP_ULP		(31)
#define N_TLS_FDS (8000)

err_t new_tls_session(void);
err_t end_tls_session(void);
err_t start_server(void);
err_t tcp_sock_configure(int);
err_t upgrade_tls_socks(void);
err_t destroy_tls_socks(void);
err_t getsockopt_all_tls(int, int, void*, void*);
err_t create_tls_socks(void);

