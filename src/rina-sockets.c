#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <dlfcn.h>
#include <rina/api.h>
#include <unistd.h> 
#include <fcntl.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/uio.h>
#include "rina-sockets-internal.h"
 
int socket(int domain, int type, int protocol) {
	static int (*my_socket)(int, int, int) = NULL;
	int fd = 0;
	int ret = 0;
	
	char* verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("socket(%d, %d, %d)...\n", domain, type, protocol);
	
	/* Open real socket, to be able to call dup2 on it later on */
	my_socket = dlsym(RTLD_NEXT, "socket");
	if (is_socket_supported(domain, type, protocol) != 0) {
		printf("Socket of domain %d, type %d not supported\n", 
				domain, type);
		fd = -1;
	} else if (!my_socket) {
		printf("Error loading socket via dlsym\n");
		errno = EACCES; 
		fd = -1;
	} else {
		fd = my_socket(domain, type, protocol);

		/* Open faux socket, to store socket state */
		ret = open_faux_socket(domain, type, protocol, fd);
		if (ret != 0) {
			close(fd);
			fd = ret;
		}
	}

	if (verbose) printf("...socket returns %d\n", fd);
	
	return fd;	
}

int close(int fd) {
	static int (*my_close)(int) = NULL;
	char * verbose = getenv("RINA_VERBOSE");
	int rc = 0;

	if (verbose) printf("close(%d)...\n", fd);
	rc = close_faux_socket(fd);
	
	my_close = dlsym(RTLD_NEXT, "close");

	rc = my_close(fd);

	if (verbose) printf("...close returns %d\n", rc);

	return rc;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	struct rina_flow_spec flow_spec;
	struct faux_socket fs;
	char * dif = getenv("RINA_DIF");
	char * local_appl = getenv("RINA_LOCAL_APPL");
	char * remote_appl = getenv("RINA_REMOTE_APPL");
	char * verbose = getenv("RINA_VERBOSE");
	char buffer[100];
	int rc, rina_fd = 0;

	if (verbose) printf("connect(%d, %p, %d)...\n", 
			    sockfd, addr, addrlen);
	
	if (!addr) {
		errno = EINVAL;
		if (verbose) 
			perror("   Destination @ is NULL\n");
	       	return -1;
	}

	/* If remote application is not set, use addr and addrlen) */
	if (!remote_appl) {
		if (get_app_name_from_addr(sockfd, addr, addrlen, buffer)) {
			errno = EINVAL;
			if (verbose)
				perror("  Problems obtaining dest app name from @");
			return -1;
		}

		remote_appl = buffer;
	}

	if (populate_rina_fspec(sockfd, &flow_spec)) {
		errno = EINVAL;
		if (verbose)
			perror("   Cannot find faux sockets with requested sockfd \n");
		return -1;
	}

	/* If RINA_LOCAL_APPL is not set, check if socket is bound */
	if (!local_appl) {
		if (get_faux_socket_data(sockfd, &fs)) {
			errno = EBADF;
			if (verbose) perror("   Unknown socket\n");
			return -1;
		}

		if (fs.bind_addrlen > 0) local_appl = fs.bind_app_name;
	}

	if (verbose) printf("  rina_fow_aloc(\"%s\", \"%s\", \"%s\", %p, 0)...\n",
			    dif, local_appl, remote_appl, &flow_spec);
	
	rina_fd = rina_flow_alloc(dif, local_appl, remote_appl, &flow_spec, 0);
		
	if (verbose) printf("  ...rina_flow_alloc returns %d\n", rina_fd);
    	
	if (rina_fd >= 0) {
		if (verbose) printf("  RINA FD = %d - swapping for %d\n", 
				    rina_fd, sockfd);
		rc = (dup2(rina_fd, sockfd) > 0) ? 0 : -1;
      		close(rina_fd);
		set_faux_socket_peer(sockfd, addr, addrlen);
	} else {
		if (verbose) perror("  rina_flow_alloc");
		rc = -1;
	}
	
	if (verbose) printf("... connect returns %d\n", rc);
	
	return rc;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	char * verbose = getenv("RINA_VERBOSE");
	struct faux_socket fs;
	int rc = 0;
  
	if (verbose) printf("bind(%d, %p, %d)...\n", sockfd, addr, addrlen);
  	
	rc = bind_faux_socket(sockfd, addr, addrlen);

	if (verbose && rc == 0) {
		get_faux_socket_data(sockfd, &fs);
		printf("  Bound to application name %s\n", 
			fs.bind_app_name);
	}

	if (verbose) printf("..bind returns %d\n", rc);
  	
	return rc;
}

int listen(int sockfd, int backlog) {
	char * dif = getenv("RINA_DIF");
	char * verbose = getenv("RINA_VERBOSE");
	char * local_appl = getenv("RINA_LOCAL_APPL");
	int rc = 0;
	int rina_fd = 0;
	struct faux_socket fs;
	
	if (verbose) printf("listen(%d, %d)...\n", sockfd, backlog);

	if ((dif == NULL) ) {
		errno = EADDRNOTAVAIL;
		if (verbose)
			perror("   Local appl name or DIF name are NULL\n");
		return -1;
	}

	/* Check if socket can be listened */
	if (get_faux_socket_data(sockfd, &fs)) {
		errno = EBADF;
		if (verbose) perror("   Unknown socket\n");
		return -1;
	}

	if ((fs.type != SOCK_STREAM) && (fs.type != SOCK_SEQPACKET)) {
		errno = EOPNOTSUPP;
		if (verbose) perror("   Listen operation not supported\n");
		return -1;
	}
	
	/* If local appl is not set, use bind address */
	if (!local_appl) local_appl = fs.bind_app_name;
	
	if (verbose) {
		printf("  rina_open()...\n");
	}
		
	rina_fd = rina_open();
		
	if (verbose) printf("  ...rina_open returns %d\n", rina_fd);
	if (rina_fd >= 0) {
		if (verbose) printf("  rina_register(%d, \"%s\", \"%s\")...\n", 
				    rina_fd, dif, local_appl);
		rc = rina_register(rina_fd, dif, local_appl, 0);

		if (verbose) printf("  ...rina_register returns %d\n", rc);
		if (rc >= 0) {
			if (verbose) printf("  RINA FD = %d - swapping for %d\n", 
					    rina_fd, sockfd);
			rc = (dup2(rina_fd, sockfd) > 0) ? 0 : -1;
			close(rina_fd);
      		} else {
			if (verbose) perror("  rina_register");
		}
	} else {
		if (verbose) perror("  rina_open");
		rc = -1;
	}
	
	if (verbose) printf("...listen returns %d\n", rc);
	
	return rc;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	char * dif = getenv("RINA_DIF");
	char * verbose = getenv("RINA_VERBOSE");
	struct faux_socket parent_fs;
	int rina_fd = 0;
	int rc = 0;
	int new_sockfd = 0;
	

	if (verbose) printf("accept(%d, %p, %p)...\n", sockfd, addr, addrlen);
	
	if ((dif == NULL)) {
		errno = EADDRNOTAVAIL;
		if (verbose)
			perror("   DIF name is NULL");
		return -1;
	}

	fd_set read_fds;
	FD_ZERO(&read_fds);
	FD_SET(sockfd, &read_fds);
		    
	if (verbose) printf("  select(%d, %p, NULL, NULL, NULL)...\n", 
			    sockfd + 1, &read_fds);
			    
	rc = select(sockfd + 1, &read_fds, NULL, NULL, NULL);
				    
	if (verbose) printf("  ...select returns %d\n", rc);
    	if (verbose) printf("  rina_flow_accept(%d, NULL, NULL, 0)...\n", 
			    sockfd);
    
	rina_fd = rina_flow_accept(sockfd, NULL, NULL, 0);
    
	if (verbose) printf("  ...rina_flow_accept returns %d\n", rina_fd);

	if (rina_fd >= 0) {
		get_faux_socket_data(sockfd, &parent_fs);
		new_sockfd = socket(parent_fs.domain, parent_fs.type, 
				    parent_fs.protocol);
		rc = (dup2(rina_fd, new_sockfd) > 0) ? new_sockfd : -1;
		close(rina_fd);
		bind(sockfd, parent_fs.bind_addr, parent_fs.bind_addrlen);


      		struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *)addr;
      		addr_in->sin6_family = AF_INET6;
      		addr_in->sin6_port = htons(50981);
      		inet_pton(AF_INET6, "::1", &(addr_in->sin6_addr));
      		*addrlen = sizeof(struct sockaddr_in6);
	} else {
      		if (verbose) perror("  rina_flow_accept");
		rc = -1;
    	}
  
	if (verbose) printf("...accept returns %d\n", rc);
  	
	return rc;
}

int accept4(int sockfd, struct sockaddr *addr, 
	    socklen_t *addrlen, int flags) {
	char * verbose = getenv("RINA_VERBOSE");
	int rc;

	if (verbose) printf("accept4(%d, %p, %p, %d)...\n", sockfd,
			     addr, addrlen, flags);

	/* Ignore flags for now */
	rc = accept(sockfd, addr, addrlen);

	if (verbose) printf("...accept4 returns %d\n", rc);
}


/*int getaddrinfo(const char *node, const char *service, 
		const struct addrinfo *hints, struct addrinfo **res) {
  	char * verbose = getenv("RINA_VERBOSE");
	int rc = 0;
	struct sockaddr_in * addr_in = NULL;
	int port = 0;
	int ai_passive = 0;

	if (verbose) printf("getaddrinfo(%s, %s, %p, %p)...\n", node, 
			    service, hints, res);

	*res = calloc(1, sizeof(struct addrinfo));
	if (!*res) {
		errno = ENOMEM;
		perror("   Problems allocating addrinfo struct");
		return EAI_MEMORY;
	}

	memset(*res, 0, sizeof(struct addrinfo));
	(*res)->ai_family = AF_INET;
	(*res)->ai_next = NULL;
	(*res)->ai_canonname = NULL;
	if (hints) {
		(*res)->ai_flags = hints->ai_flags;
		(*res)->ai_socktype = hints->ai_socktype;
		(*res)->ai_protocol = hints->ai_protocol;
		if (hints->ai_flags & AI_PASSIVE) ai_passive = 1;
	}
	
	(*res)->ai_addr = calloc(1, sizeof(struct sockaddr_in));
	if ((*res)->ai_addr == NULL) {
		errno = ENOMEM;
		perror("   Problems allocating sockaddr_in struct");
		free(*res);
		return EAI_MEMORY;
	}
	
	/* Resolve to an IPv4 address */
/*	(*res)->ai_addrlen = sizeof(struct sockaddr_in);
	addr_in = (struct sockaddr_in *)(*res)->ai_addr;
	addr_in->sin_family = AF_INET;

	if (service) {
		port = atoi(service);
		if (port > 0) { 
			addr_in->sin_port = htons(port);
		} else {
			errno = EINVAL;
			perror("   Problems converting service to int");
			free(*res);
			return EAI_SERVICE;
		}
	}

	if (verbose) printf("   Resolved sin_port %d\n", addr_in->sin_port);

	if (ai_passive && !node) {
		addr_in->sin_addr.s_addr = htonl(INADDR_ANY);
	} else if (!node) {
		addr_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	} else {
		inet_aton(node, &addr_in->sin_addr);
	}

	if (verbose) printf("   Resolved IPv4 address %d\n", 
			    addr_in->sin_addr.s_addr);
  
	if (verbose) printf("...getaddrinfo returns 0\n");
  	
	return 0;
}*/

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	char * verbose = getenv("RINA_VERBOSE");
	struct sockaddr_in * addr_in = NULL;
	int rc;

	if (verbose) printf("getsockname(%d, %p, %p)...\n", sockfd, 
			    addr, addrlen);

	if (!addrlen || !addr) {
		errno = EINVAL;
		perror("   Address or Address lenght are null");
		return -1;
	}

	rc = get_faux_sockname(sockfd, addr, addrlen);
	
	if (verbose) printf("...getsockname returns %d\n", rc);

	return rc;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	char * verbose = getenv("RINA_VERBOSE");
	int rc;

	if (verbose) printf("getpeername(%d, %p, %p)...\n", 
			    sockfd, addr, addrlen);

	if (!addrlen || !addr) {
		errno = EINVAL;
		perror("   Address or Address length are null");
		return -1;
	}

	rc = get_faux_peername(sockfd, addr, addrlen);

	if (verbose) printf("...getpeername returns %d\n", rc);

	return rc;
}

int getsockopt(int sockfd, int level, int optname, 
	       void *optval, socklen_t *optlen) {
	char * verbose = getenv("RINA_VERBOSE");
	int rc;
	int * val;

	if (verbose) printf("getsockopt(%d, %d, %d, %p, %p)...\n", sockfd,
			     level, optname, optval, optlen);

	if (!optval || !optlen) {
		errno = EINVAL;
		perror("   optcal or optlen are null");
		return -1;
	}

	rc = get_faux_sockopt_value(optname, optlen); 
	val = (int *) optval;
	*val = rc;

	if (verbose) printf("...getsockopt returns 0\n");

	return 0;
}

int setsockopt(int sockfd, int level, int optname,
	       const void *optval, socklen_t optlen) {
	char * verbose = getenv("RINA_VERBOSE");
	int rc;

	if (verbose) printf("setsockopt(%d, %d, %d, %p, %d)...\n", sockfd,
			     level, optname, optval, optlen);

	rc = store_faux_sockopt(level, optname, optval, optlen);
	
	if (verbose) printf("...setsockopt returns %d\n", rc);

	return rc;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
	char * verbose = getenv("RINA_VERBOSE");
	int rv = 0;

	if (verbose) printf("recv(%d, %p, %d, %d)...\n", 
			    sockfd, buf, len, flags);

	/* Ignore flags for now*/
	rv = read(sockfd, buf, len);

	if (verbose) printf("...recv returns %d\n", rv);

	return rv;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *addrlen) {
	char * verbose = getenv("RINA_VERBOSE");
	int rv = 0;

	if (verbose) printf("recvfrom(%d, %p, %d, %p, %p)...\n", sockfd,
				buf, len, flags, src_addr, addrlen);

	/* Ignore flags and address for now */
	rv = read(sockfd, buf, len);

	if (verbose) printf("...recvfrom returns %d\n", rv);

	return rv;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
	char * verbose = getenv("RINA_VERBOSE");
	int rv = 0;

	if (verbose) printf("recvmsg(%d, %p, %d), ...\n", sockfd, 
			msg, flags);

	/* Ignore flags for now */	
	rv = readv(sockfd, msg->msg_iov, msg->msg_iovlen);

	if (verbose) printf("...recvmsg returns %d\n", rv);

	return rv;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
	char * verbose = getenv("RINA_VERBOSE");
	int rv = 0;

	if (verbose) printf("send(%d, %p, %d, %d),...\n", sockfd, buf,
				len, flags);

	/* Ignore flags for now */
	rv = write(sockfd, buf, len);

	if (verbose) printf("...send returns %d\n", rv);

	return rv;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen){
	char * verbose = getenv("RINA_VERBOSE");
	int rv = 0;

	if (verbose) printf("sendto(%d, %p, %d, %d, %p, %d),...\n", sockfd, 
				buf, len, flags, dest_addr, addrlen);

	/* Ignore flags and address for now */
	rv = write(sockfd, buf, len);

	if (verbose) printf("...sendto returns %d\n", rv);

	return rv;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
	char * verbose = getenv("RINA_VERBOSE");
	int rv = 0;

	if (verbose) printf("sendmsg(%d, %p, %d), ...\n", sockfd,
			    msg, flags);

	/* Ignore flags for now */
	rv = writev(sockfd, msg->msg_iov, msg->msg_iovlen);

	if (verbose) printf("...sendmsg returns %d\n", rv);

	return rv;
}

int shutdown(int sockfd, int how) {
	char * verbose = getenv("RINA_VERBOSE");
	int rv = 0;

	if (verbose) printf("shutdown(%d, %d), ...\n", sockfd, how);

	/* Ignore how for now */
	rv = close(sockfd);

	if (verbose) printf("...shutdown returns %d\n", rv);

	return rv;
}
