#define _GNU_SOURCE
#include "syshead.h"
#include "liblevelip.h"
#include "ipc.h"
#include "list.h"
#include "utils.h"

#include <pthread.h>

// stack trace
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define RCBUF_LEN 512

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static int (*_fcntl)(int fildes, int cmd, ...) = NULL;
static int (*_setsockopt)(int fd, int level, int optname,
                         const void *optval, socklen_t optlen) = NULL;
static int (*_getsockopt)(int fd, int level, int optname,
                         const void *optval, socklen_t *optlen) = NULL;
static int (*_read)(int sockfd, void *buf, size_t len) = NULL;
static int (*_write)(int sockfd, const void *buf, size_t len) = NULL;
static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int fildes) = NULL;
static int (*_poll)(struct pollfd fds[], nfds_t nfds, int timeout) = NULL;
static int (*_pollchk)(struct pollfd *__fds, nfds_t __nfds, int __timeout,
                       __SIZE_TYPE__ __fdslen) = NULL;

static int (*_ppoll)(struct pollfd *fds, nfds_t nfds,
                     const struct timespec *tmo_p, const sigset_t *sigmask) = NULL;
static int (*_select)(int nfds, fd_set *restrict readfds,
                      fd_set *restrict writefds, fd_set *restrict errorfds,
                      struct timeval *restrict timeout);
static ssize_t (*_sendto)(int sockfd, const void *message, size_t length,
                          int flags, const struct sockaddr *dest_addr,
                          socklen_t dest_len) = NULL;
static ssize_t (*_recvfrom)(int sockfd, void *buf, size_t len,
                            int flags, struct sockaddr *restrict address,
                            socklen_t *restrict addrlen) = NULL;
static int (*_getpeername)(int socket, struct sockaddr *restrict address,
                           socklen_t *restrict address_len) = NULL;
static int (*_getsockname)(int socket, struct sockaddr *restrict address,
                           socklen_t *restrict address_len) = NULL;

static int lvlip_socks_count = 0;
static LIST_HEAD(lvlip_socks);

static int callorder = 0;
void init_if_needed(void);

static inline struct lvlip_sock *lvlip_get_sock(int fd) {
    struct list_head *item;
    struct lvlip_sock *sock;

    list_for_each(item, &lvlip_socks) {
        sock = list_entry(item, struct lvlip_sock, list);
        
        if (sock->fd == fd) return sock;
    };

    return NULL;
};

static int is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET) return 0;

    if (!(type & SOCK_STREAM)) return 0;

    if (protocol != 0 && protocol != IPPROTO_TCP) return 0;

    return 1;
}

static int init_socket(char *sockname)
{lvl_dbg("init_socket called\n");
    struct sockaddr_un addr;
    int ret;
    int data_socket;

    /* Create local socket. */

    data_socket = _socket(AF_UNIX, SOCK_STREAM, 0);
    if (data_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /*
     * For portability clear the whole structure, since some
     * implementations have additional (nonstandard) fields in
     * the structure.
     */

    memset(&addr, 0, sizeof(struct sockaddr_un));

    /* Connect socket to socket address */

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockname, sizeof(addr.sun_path) - 1);

    ret = _connect(data_socket, (const struct sockaddr *) &addr,
                   sizeof(struct sockaddr_un));
    if (ret == -1) {
        print_err("Error connecting to level-ip. Is it up?\n");
        exit(EXIT_FAILURE);
    }

    return data_socket;
}

static int free_socket(int lvlfd)
{lvl_dbg("free_socket called\n");
    return _close(lvlfd);
}

static int transmit_lvlip(int lvlfd, struct ipc_msg *msg, int msglen)
{lvl_dbg("transmit_lvlip called\n");
    char *buf[RCBUF_LEN];

    // Send mocked syscall to lvl-ip
    if (_write(lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC");
    }

    // Read return value from lvl-ip
    if (_read(lvlfd, buf, RCBUF_LEN) == -1) {
        perror("Could not read IPC response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) buf;

    if (response->type != msg->type || response->pid != msg->pid) {
        print_err("ERR: IPC msg response expected type %d, pid %d\n"
                  "                      actual type %d, pid %d\n",
               msg->type, msg->pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *err = (struct ipc_err *) response->data;

    if (err->rc == -1) errno = err->err;
lvl_dbg("transmit_lvlip exiting with fd %i\n", err->rc);
    return err->rc;
}

int socket(int domain, int type, int protocol)
{lvl_dbg("socket called\n");
	init_if_needed();
    if (!is_socket_supported(domain, type, protocol)) {
lvl_dbg("socket exiting, loop-through - domain = %i, type = %i, protocol = %i. AF_INET = %i, SOCK_STREAM = %i, IPPROTO_TCP = %i\n", domain, type, protocol, AF_INET, SOCK_STREAM, IPPROTO_TCP);		
        return _socket(domain, type, protocol);
    }

    struct lvlip_sock *sock;
    
    int lvlfd = init_socket("/tmp/lvlip.socket");

    sock = lvlip_alloc();
    sock->lvlfd = lvlfd;
    list_add_tail(&sock->list, &lvlip_socks);
    lvlip_socks_count++;
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_socket);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_SOCKET;
    msg->pid = pid;

    struct ipc_socket usersock = {
        .domain = domain,
        .type = type,
        .protocol = protocol
    };
    
    memcpy(msg->data, &usersock, sizeof(struct ipc_socket));

    int sockfd = transmit_lvlip(sock->lvlfd, msg, msglen);

    if (sockfd == -1) {
        /* Socket alloc failed */
        lvlip_free(sock);
lvl_dbg("socket exiting, failed\n");		
        return -1;
    }

    sock->fd = sockfd;

    lvl_sock_dbg("Socket called", sock);
lvl_dbg("socket exiting, fd = %i\n", sockfd);
    return sockfd;
}

int close(int fd)
{lvl_dbg("close called on %i\n", fd);
	init_if_needed();
    struct lvlip_sock *sock = lvlip_get_sock(fd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return _close(fd);
    }

    lvl_sock_dbg("Close called", sock);
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_close);
    int rc = 0;

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_CLOSE;
    msg->pid = pid;

    struct ipc_close *payload = (struct ipc_close *)msg->data;
    payload->sockfd = fd;

    rc = transmit_lvlip(sock->lvlfd, msg, msglen);
    free_socket(sock->lvlfd);

    return rc;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{lvl_dbg("connect called\n");
	init_if_needed();
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return _connect(sockfd, addr, addrlen);
    }

    lvl_sock_dbg("Connect called", sock);
    
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_connect);
    int pid = getpid();
    
    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_CONNECT;
    msg->pid = pid;

    struct ipc_connect payload = {
        .sockfd = sockfd,
        .addr = *addr,
        .addrlen = addrlen
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_connect));

    return transmit_lvlip(sock->lvlfd, msg, msglen);
}

ssize_t write(int sockfd, const void *buf, size_t len)
{lvl_dbg("write called\n");
	init_if_needed();
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return _write(sockfd, buf, len);
    }

    lvl_sock_dbg("Write called", sock);
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_write) + len;
    int pid = getpid();

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_WRITE;
    msg->pid = pid;

    struct ipc_write payload = {
        .sockfd = sockfd,
        .len = len
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_write));
    memcpy(((struct ipc_write *)msg->data)->buf, buf, len);

    return transmit_lvlip(sock->lvlfd, msg, msglen);
}

ssize_t read(int sockfd, void *buf, size_t len)
{lvl_dbg("read called on fd %i, callorder %i, thread = %i\n", sockfd, callorder, (int)pthread_self());
	init_if_needed();
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
		if (_read == NULL) {
			callorder = 2;
			_read = dlsym(RTLD_NEXT, "read");
		}
		lvl_dbg("wrapped read, len = %i\n", len);
        return _read(sockfd, buf, len);
    }

    lvl_sock_dbg("Read called", sock);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_read);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_READ;
    msg->pid = pid;

    struct ipc_read payload = {
        .sockfd = sockfd,
        .len = len
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_read));

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC read");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_read) + len;
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC read response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_READ || response->pid != pid) {
        print_err("ERR: IPC read response expected: type %d, pid %d\n"
                  "                       actual: type %d, pid %d\n",
               IPC_READ, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc < 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_read *data = (struct ipc_read *) error->data;
    if (len < data->len) {
        print_err("IPC read received len error: %u\n", data->len);
        return -1;
    }

    memset(buf, 0, len);
    memcpy(buf, data->buf, data->len);
        
    return data->len;
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{

    return sendto(fd, buf, len, flags, NULL, 0);
}

ssize_t sendto(int fd, const void *buf, size_t len,
               int flags, const struct sockaddr *dest_addr,
               socklen_t dest_len)
{lvl_dbg("sendto called\n");
	init_if_needed();
    if (!lvlip_get_sock(fd)) return _sendto(fd, buf, len,
                                        flags, dest_addr, dest_len);

    return write(fd, buf, len);
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    return recvfrom(fd, buf, len, flags, NULL, 0);
}

ssize_t recvfrom(int fd, void *restrict buf, size_t len,
                 int flags, struct sockaddr *restrict address,
                 socklen_t *restrict addrlen)
{lvl_dbg("recvfrom called\n");
	init_if_needed();
    if (!lvlip_get_sock(fd)) return _recvfrom(fd, buf, len,
                                          flags, address, addrlen);

    return read(fd, buf, len);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{lvl_dbg("poll called\n");
	init_if_needed();
    struct pollfd *kernel_fds[nfds];
    struct pollfd *lvlip_fds[nfds];
    int lvlip_nfds = 0;
    int kernel_nfds = 0;
    int lvlip_sock = 0;

    struct lvlip_sock *sock = NULL;

    for (int i = 0; i < nfds; i++) {
        struct pollfd *pfd = &fds[i];
        if ((sock = lvlip_get_sock(pfd->fd)) != NULL) {
            lvlip_fds[lvlip_nfds++] = pfd;
            lvlip_sock = sock->lvlfd;
        } else {
            kernel_fds[kernel_nfds++] = pfd;
        }
    }

    int blocking = 0;
    if (kernel_nfds > 0 && lvlip_nfds > 0 && timeout == -1) {
        /* Cannot sleep indefinitely when we demux poll 
           with both kernel and lvlip fds */
        timeout = 100;
        blocking = 1;
    }

    lvl_dbg("Poll called with kernel_nfds %d lvlip_nfds %d timeout %d", kernel_nfds, lvlip_nfds, timeout);

    for (;;) {
        int events = 0;
        if (kernel_nfds > 0) {
            for (int i = 0; i < kernel_nfds; i++) {
                lvl_dbg("Kernel nfd %d events %d timeout %d", kernel_fds[i]->fd, kernel_fds[i]->events, timeout);
            }
            
            events = _poll(*kernel_fds, kernel_nfds, timeout);

            if (events == -1) {
                perror("Poll kernel error");
                errno = EAGAIN;
                return -1;
            }
        }

        if (lvlip_nfds < 1) {
            return events;
        }
    
        int pid = getpid();
        int pollfd_size = sizeof(struct ipc_pollfd);
        int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_poll) + pollfd_size * lvlip_nfds;
        struct ipc_msg *msg = alloca(msglen);

        msg->type = IPC_POLL;
        msg->pid = pid;

        struct ipc_poll *data = (struct ipc_poll *)msg->data;
        data->nfds = lvlip_nfds;
        data->timeout = timeout;

        struct ipc_pollfd *pfd = NULL;
        for (int i = 0; i < lvlip_nfds; i++) {
            pfd = &data->fds[i];
            pfd->fd = lvlip_fds[i]->fd;
            pfd->events = lvlip_fds[i]->events;
            pfd->revents = lvlip_fds[i]->revents;
        }

        if (_write(lvlip_sock, (char *)msg, msglen) == -1) {
            perror("Error on writing IPC poll");
            errno = EAGAIN;
            return -1;
        }

        int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + pollfd_size * lvlip_nfds;
        char rbuf[rlen];
        memset(rbuf, 0, rlen);

        // Read return value from lvl-ip
        if (_read(lvlip_sock, rbuf, rlen) == -1) {
            perror("Could not read IPC poll response");
            errno = EAGAIN;
            return -1;
        }
    
        struct ipc_msg *response = (struct ipc_msg *) rbuf;

        if (response->type != IPC_POLL || response->pid != pid) {
            print_err("ERR: IPC poll response expected: type %d, pid %d\n"
                   "                       actual: type %d, pid %d\n",
                   IPC_POLL, pid, response->type, response->pid);
            errno = EAGAIN;
            return -1;
        }

        struct ipc_err *error = (struct ipc_err *) response->data;
        if (error->rc < 0) {
            errno = error->err;
            print_err("Error on poll %d %s\n", error->rc, strerror(errno));
            return error->rc;
        }

        struct ipc_pollfd *returned = (struct ipc_pollfd *) error->data;

        for (int i = 0; i < lvlip_nfds; i++) {
            lvlip_fds[i]->events = returned[i].events;
            lvlip_fds[i]->revents = returned[i].revents;
        }

        int result = events + error->rc;
    
        if (result > 0 || !blocking) {
            for (int i = 0; i < nfds; i++) {
                lvl_dbg("Returning counts %d nfd %d with revents %d events %d timeout %d", result, i, fds[i].revents, fds[i].events, timeout);
            }
 
            return result;
        } 
    }

    print_err("Poll returning with -1\n");
    return -1;
}

int __poll_chk (struct pollfd *__fds, nfds_t __nfds, int __timeout,
                __SIZE_TYPE__ __fdslen)
{lvl_dbg("__poll_chk called\n");
	init_if_needed();
    return poll(__fds, __nfds, __timeout);
}

int ppoll(struct pollfd *fds, nfds_t nfds,
          const struct timespec *tmo_p, const sigset_t *sigmask)
{
    print_err("Ppoll called but not supported\n");
    return -1;
}

int select(int nfds, fd_set *restrict readfds,
           fd_set *restrict writefds, fd_set *restrict errorfds,
           struct timeval *restrict timeout)
{lvl_dbg("select called\n");
    print_err("Select not implemented yet\n");
    return _select(nfds, readfds, writefds, errorfds, timeout);
}


int setsockopt(int fd, int level, int optname,
               const void *optval, socklen_t optlen)
{lvl_dbg("setsockopt called\n");
	init_if_needed();
    struct lvlip_sock *sock = lvlip_get_sock(fd);
    if (sock == NULL) return _setsockopt(fd, level, optname, optval, optlen);

    lvl_sock_dbg("Setsockopt called", sock);

    /* WARN: Setsockopt not supported yet */
    
    return 0;
}

int getsockopt(int fd, int level, int optname,
               void *optval, socklen_t *optlen)
{
lvl_dbg("getsockopt called\n");
	init_if_needed();
    struct lvlip_sock *sock = lvlip_get_sock(fd);
    if (sock == NULL) return _getsockopt(fd, level, optname, optval, optlen);

    lvl_sock_dbg("getsockopt called: level %d optname %d optval %d socklen %d",
                 sock, level, optname, *(int *)optval, *optlen);
// lvl_dbg("SOL_SOCKET = %i, SO_BINDTODEVICE=%i, SO_REUSEADDR=%i, SO_BROADCAST=%i, SO_ERROR=%i\n", SOL_SOCKET, SO_BINDTODEVICE, SO_REUSEADDR, SO_BROADCAST, SO_ERROR);
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sockopt) + *optlen;

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_GETSOCKOPT;
    msg->pid = pid;

    //struct ipc_sockopt opts = {
    //    .fd = fd,
    //    .level = level,
    //    .optname = optname,
    //    .optlen = *optlen,
    //};
	//
    //memcpy(&opts.optval, optval, *optlen);
	//struct ipc_sockopt *opts = alloca(sizeof(struct ipc_sockopt) + *optlen);
	struct ipc_sockopt *opts = (struct ipc_sockopt *) msg->data;
	opts->fd = fd;
	opts->level = level;
	opts->optname = optname;
	opts->optlen = *optlen;
	memcpy(opts->optval, optval, *optlen);
	
    //memcpy(msg->data, opts, sizeof(struct ipc_sockopt) + *optlen);

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC getsockopt");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockopt) + *optlen + 1000;
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC getsockopt response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_GETSOCKOPT || response->pid != pid) {
        print_err("ERR: IPC getsockopt response expected: type %d, pid %d\n"
               "                          actual: type %d, pid %d\n",
               IPC_GETSOCKOPT, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc != 0) {
        errno = error->err;
lvl_dbg("getsockopt error exit, errno = %i, error->rc = %i\n", errno, error->rc);		
        return error->rc;
    }

    struct ipc_sockopt *optres = (struct ipc_sockopt *) error->data;

    lvl_sock_dbg("Got getsockopt level %d optname %d optval %d socklen %d",
                 sock, optres->level, optres->optname, *(int *)optres->optval, optres->optlen);

    int val = *(int *)optres->optval;

    /* lvl-ip probably encoded the error value as negative */
    val *= -1;
// assumes a single int return value
lvl_dbg("getsockopt write value = %i, to address = %x\n", val, (int) optval);
    *(int *)optval = val;
    *optlen = optres->optlen;
lvl_dbg("getsockopt exiting\n"); sync(); sync();
    return 0;
}

int getpeername(int socket, struct sockaddr *restrict address,
                socklen_t *restrict address_len)
{lvl_dbg("getpeername called\n");
	init_if_needed();
    struct lvlip_sock *sock = lvlip_get_sock(socket);
    if (sock == NULL) return _getpeername(socket, address, address_len);

    lvl_sock_dbg("Getpeername called", sock);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sockname);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_GETPEERNAME;
    msg->pid = pid;

    struct ipc_sockname *name = (struct ipc_sockname *)msg->data;
    name->socket = socket;

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC getpeername");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockname);
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC getpeername response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_GETPEERNAME || response->pid != pid) {
        print_err("ERR: IPC getpeername response expected: type %d, pid %d\n"
               "                          actual: type %d, pid %d\n",
               IPC_GETPEERNAME, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc != 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_sockname *nameres = (struct ipc_sockname *) error->data;

    lvl_sock_dbg("Got getpeername fd %d addrlen %d sa_data %p",
                 sock, nameres->socket, nameres->address_len, nameres->sa_data);

    if (nameres->socket != socket) {
        print_err("Got socket %d but requested %d\n", nameres->socket, socket);
    }

    *address_len = nameres->address_len;
    memcpy(address, nameres->sa_data, nameres->address_len);
    
    return 0;
}

int getsockname(int socket, struct sockaddr *restrict address,
                socklen_t *restrict address_len)
{lvl_dbg("getsockname called\n");
	init_if_needed();
    struct lvlip_sock *sock = lvlip_get_sock(socket);
    if (sock == NULL) return _getsockname(socket, address, address_len);

    lvl_sock_dbg("Getsockname called", sock);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sockname);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_GETSOCKNAME;
    msg->pid = pid;

    struct ipc_sockname *name = (struct ipc_sockname *)msg->data;
    name->socket = socket;

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC getsockname");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockname);
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC getsockname response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_GETSOCKNAME || response->pid != pid) {
        print_err("ERR: IPC getsockname response expected: type %d, pid %d\n"
               "                          actual: type %d, pid %d\n",
               IPC_GETSOCKNAME, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc != 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_sockname *nameres = (struct ipc_sockname *) error->data;

    lvl_sock_dbg("Got getsockname fd %d addrlen %d sa_data %p",
                 sock, nameres->socket, nameres->address_len, nameres->sa_data);

    if (nameres->socket != socket) {
        print_err("Got socket %d but requested %d\n", nameres->socket, socket);
    }

    *address_len = nameres->address_len;
    memcpy(address, nameres->sa_data, nameres->address_len);

    return 0;
}

int fcntl(int fildes, int cmd, ...)
{lvl_dbg("fcntl called on fidles %i, cmd = %i\n", fildes, cmd);
	init_if_needed();
    int rc = -1;
    va_list ap;
    void *arg;

    struct lvlip_sock *sock = lvlip_get_sock(fildes);
    if (!sock) {
        va_start(ap, cmd);
        arg = va_arg(ap, void *);
        va_end(ap);
        return _fcntl(fildes, cmd, arg);
    }
    lvl_sock_dbg("Fcntl called", sock);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_fcntl) + sizeof(struct flock) + sizeof(int);
    struct ipc_msg *msg = alloca(msglen);

    msg->type = IPC_FCNTL;
    msg->pid = pid;

    struct ipc_fcntl *fc = (struct ipc_fcntl *)msg->data;
    fc->sockfd = fildes;
	
    fc->cmd = cmd;
    switch (cmd) {
    case F_GETFL:
        lvl_sock_dbg("Fcntl GETFL", sock);

        rc = transmit_lvlip(sock->lvlfd, msg, msglen);
        break;
    case F_SETFL:
        lvl_sock_dbg("Fcntl SETFL", sock);

        va_start(ap, cmd);

        int flags = va_arg(ap, int);
        memcpy(fc->data, &flags, sizeof(int));

        va_end(ap);

        rc = transmit_lvlip(sock->lvlfd, msg, msglen);
        break;
    default:
        rc = -1;
        errno = EINVAL;
        break;
    }
lvl_dbg("fcntl exited\n");    
    return rc;
}

/*
// nope -doesn't work
void stack_trace(void) {
	int j, nptrs;
#define SIZE 100
    void *buffer[SIZE];
    char **strings;

    nptrs = backtrace(buffer, SIZE);
    printf("backtrace() returned %d addresses\n", nptrs);

    //The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
    //   would produce similar output to the following: 

   strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        perror("backtrace_symbols");
        exit(EXIT_FAILURE);
    }

   for (j = 0; j < nptrs; j++)
        printf("%s\n", strings[j]);

   free(strings);
	
}
*/

void init_if_needed(void) {
	//lvl_dbg("__libc_start_main init, callorder = %i, thread = %i\n", callorder, (int)pthread_self());
	if (callorder == 0) {
		//stack_trace(); // see who called?
		lvl_dbg("__libc_start_main init post-check, callorder = %i, thread = %i\n", callorder, (int)pthread_self());
		callorder = 10;
		
		_sendto = dlsym(RTLD_NEXT, "sendto");
		_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
		_poll = dlsym(RTLD_NEXT, "poll");
		_ppoll = dlsym(RTLD_NEXT, "ppoll");
		_pollchk = dlsym(RTLD_NEXT, "__poll_chk");
		_select = dlsym(RTLD_NEXT, "select");
		_fcntl = dlsym(RTLD_NEXT, "fcntl"); 
		_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
		_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
		_read = dlsym(RTLD_NEXT, "read");
		_write = dlsym(RTLD_NEXT, "write");
		_connect = dlsym(RTLD_NEXT, "connect");
		_socket = dlsym(RTLD_NEXT, "socket");
		_close = dlsym(RTLD_NEXT, "close");
		_getpeername = dlsym(RTLD_NEXT, "getpeername");
		_getsockname = dlsym(RTLD_NEXT, "getsockname");
	
		list_init(&lvlip_socks);
	}
	//lvl_dbg("__libc_start_main init - exit, callorder = %i, thread = %i\n", callorder, (int)pthread_self());
}	

int __libc_start_main(int (*main) (int, char * *, char * *), int argc,
                      char * * ubp_av, void (*init) (void), void (*fini) (void),
                      void (*rtld_fini) (void), void (* stack_end))
{
lvl_dbg("__libc_start_main called, callorder = %i, thread = %i\n", callorder, (int)pthread_self());
	init_if_needed();
	
	__start_main = dlsym(RTLD_NEXT, "__libc_start_main");
	
/*
lvl_dbg("__libc_start_main exiting\n");
lvl_dbg("__libc_start_main symbols: %i\n", (int)_sendto);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_recvfrom);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_poll);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_ppoll);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_pollchk);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_select);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_fcntl);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_setsockopt);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_getsockopt);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_read);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_write);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_connect);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_socket);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_close);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_getpeername);
lvl_dbg("__libc_start_main symbols: %i\n", (int)_getsockname);
*/


    return __start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

/* // supposed to be called at initialisation, but other functions have already been called by then...
// https://stackoverflow.com/questions/9759880/automatically-executed-functions-when-loading-shared-libraries
__attribute__((constructor)) static void initialize() {
  lvl_dbg("initialize called; callorder = %i\n", callorder);
  
}
*/

