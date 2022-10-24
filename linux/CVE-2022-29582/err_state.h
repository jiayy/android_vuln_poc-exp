#ifndef ERR_STATE_H
#define ERR_STATE_H

#define SUCC (0)
#define ERR (-1)
#define ERR_PTR (NULL)
#define ERR_UNFIN(i) ((i > 0) ? i : ERR)

#define IS_ERR(i) (i == -1)
#define IS_ERR_PTR(i) (i == NULL)

#define IF_ERR(i)       \
        if (IS_ERR(i))  \

#define IF_ERR_PTR(i)       \
        if (IS_ERR_PTR(i))  \

#define IF_ERR_BREAK(i) \
        IF_ERR(i) {     \
            break;      \
        }

#define IF_ERR_PTR_BREAK(i) \
        IF_ERR_PTR(i) {     \
            break;          \
        }

#define IF_ERR_RET(i)   \
        IF_ERR(i) {     \
            return ERR; \
        }

#define IF_ERR_PTR_RET(i)   \
        IF_ERR_PTR(i) {     \
            return ERR; \
        }

static inline int XCHNG_FD(int i, int j) {
    int x = j; j = i; return x;
}

/* When this is the return type it means that
 * the return value encodes only success/failure.
 * Contrary to encoding data or reference to data. */
typedef int err_t;

#endif // ERR_STATE_H
