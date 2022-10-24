#include <arpa/inet.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "netlink.h"

struct nlmsghdr *get_batch_begin_nlmsg(void) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct nfgenmsg)));
    struct nfgenmsg *nfgm = (struct nfgenmsg *)NLMSG_DATA(nlh);

    if (!nlh) {
        die("malloc: %m");
    }

    memset(nlh, 0, NLMSG_SPACE(sizeof(struct nfgenmsg)));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct nfgenmsg));
    nlh->nlmsg_type = NFNL_MSG_BATCH_BEGIN;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_seq = 0;

    /* Used to access to the netfilter tables subsystem */
    nfgm->res_id = NFNL_SUBSYS_NFTABLES;

    return nlh;
}

struct nlmsghdr *get_batch_end_nlmsg(void) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct nfgenmsg)));

    if (!nlh) {
        die("malloc: %m");
    }

    memset(nlh, 0, NLMSG_SPACE(sizeof(struct nfgenmsg)));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct nfgenmsg));
    nlh->nlmsg_type = NFNL_MSG_BATCH_END;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 0;

    return nlh;
}

struct nlattr *set_nested_attr(struct nlattr *attr, uint16_t type, uint16_t data_len) {
    attr->nla_type = type;
    attr->nla_len = NLA_ALIGN(data_len + sizeof(struct nlattr));
    return (void *)attr + sizeof(struct nlattr);
}

struct nlattr *set_u32_attr(struct nlattr *attr, uint16_t type, uint32_t value) {
    attr->nla_type = type;
    attr->nla_len = U32_NLA_SIZE;
    *(uint32_t *)NLA_ATTR(attr) = htonl(value);

    return (void *)attr + U32_NLA_SIZE;
}

struct nlattr *set_u64_attr(struct nlattr *attr, uint16_t type, uint64_t value) {
    attr->nla_type = type;
    attr->nla_len = U64_NLA_SIZE;
    *(uint64_t *)NLA_ATTR(attr) = htobe64(value);

    return (void *)attr + U64_NLA_SIZE;
}

struct nlattr *set_str8_attr(struct nlattr *attr, uint16_t type, const char name[8]) {
    attr->nla_type = type;
    attr->nla_len = S8_NLA_SIZE;
    memcpy(NLA_ATTR(attr), name, 8);

    return (void *)attr + S8_NLA_SIZE;
}

struct nlattr *set_binary_attr(struct nlattr *attr, uint16_t type, uint8_t *buffer, uint64_t buffer_size) {
    attr->nla_type = type;
    attr->nla_len = NLA_BIN_SIZE(buffer_size);
    memcpy(NLA_ATTR(attr), buffer, buffer_size);

    return (void *)attr + NLA_ALIGN(NLA_BIN_SIZE(buffer_size));
}
