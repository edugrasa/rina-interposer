#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <dlfcn.h>
#include <rina/api.h>
#include <unistd.h> 
#include <fcntl.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "rina-sockets-internal.h"
 
int socket(int domain, int type, int protocol) {
	struct faux_socket * fs;
	int fd;
	
	char* verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("socket(%d, %d, %d)...\n", domain, type, protocol);
	
	fd = open_faux_socket(domain, type, protocol, fs);

	if (verbose) printf("...returns %d\n", fd);
	
	return fd;	
}

int close(int fd) {
	static int (*my_close)(int) = NULL;
	char * verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("close(%d)...\n", fd);
	close_faux_socket(fd);
	
	my_close = dlsym(RTLD_NEXT, "close");

	return my_close(fd);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	struct faux_socket * fs;
	struct rina_flow_spec flow_spec;
	char * dif = getenv("RINA_DIF");
	char * local_appl = getenv("RINA_LOCAL_APPL");
	char * remote_appl = getenv("RINA_REMOTE_APPL");
	char * verbose = getenv("RINA_VERBOSE");
	int rc;

	if (verbose) printf("connect(%d, %p, %d)...\n", sockfd, addr, addrlen);
	
	if ((local_appl == NULL) || (remote_appl == NULL)) {
		errno = EADDRNOTAVAIL;
		if (verbose) 
			perror("   Local appl name or Remote appl name are NULL\n");
	       	return -1;
	}

	if (verbose) printf("  RINA_DIF=%s, RINA_LOCAL_APPL=%s, RINA_REMOTE_APPL=%s => RINA interposer enabled!\n", dif, local_appl, remote_appl);
	if (verbose) printf("  rina_flow_alloc(\"%s\", \"%s\", \"%s\", NULL, 0)...\n", dif, local_appl, remote_appl);
	
	if (get_faux_socket(sockfd, fs) != 0) {
		errno = EINVAL;
		if (verbose)
			perror("   Cannot find faux sockets with requested sockfd \n");
		return -1;
	}
	
	populate_rina_fspec(fs, &flow_spec);

	int rina_fd = rina_flow_alloc(dif, local_appl, remote_appl, &flow_spec, 0);
		
	if (verbose) printf("  ...returns %d\n", rina_fd);
    	
	fs->rinafd = rina_fd;

	if (rina_fd >= 0) {
		if (verbose) printf("  RINA FD = %d - swapping for %d\n", rina_fd, sockfd);
		rc = (dup2(rina_fd, sockfd) > 0) ? 0 : -1;
      		close(rina_fd);
	} else {
		if (verbose) perror("  rina_flow_alloc");
		rc = -1;
	}
	
	if (verbose) printf("...returns %d\n", rc);
	
	return rc;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  	char * dif = getenv("RINA_DIF");
	char * local_appl = getenv("LOCAL_APPL");
	char * verbose = getenv("RINA_VERBOSE");
	int rc = 0;
  
	if (verbose) printf("bind(%d, %p, %d)...\n", sockfd, addr, addrlen);
  	
 	if ((dif == NULL) || (local_appl == NULL)) {
		errno = EADDRNOTAVAIL;
		if (verbose)
			perror("   Local appl name or DIF name are NULL\n");
		return -1;
	}

	if (verbose) {
		printf("  RINA_DIF=%s, RINA_LOCAL_APPL=%s => RINA interposer enabled!\n", dif, local_appl);
		printf("...returns %d\n", rc);
	}
  	
	return rc;
}

int listen(int sockfd, int backlog) {
	char * dif = getenv("RINA_DIF");
	char * local_appl = getenv("LOCAL_APPL");
	char * verbose = getenv("RINA_VERBOSE");
	int rc = 0;
	int rina_fd = 0;
	
	if (verbose) printf("listen(%d, %d)...\n", sockfd, backlog);

	if ((dif == NULL) || (local_appl == NULL)) {
		errno = EADDRNOTAVAIL;
		if (verbose)
			perror("   Local appl name or DIF name are NULL\n");
		return -1;
	}	
		
	if (verbose) {
		printf("  RINA_DIF=%s, RINA_LOCAL_APPL=%s => RINA interposer enabled!\n", dif, local_appl);
		printf("  rina_open()...\n");
	}
		
	rina_fd = rina_open();
		
	if (verbose) printf("  ...returns %d\n", rina_fd);
	if (rina_fd >= 0) {
		if (verbose) printf("  rina_register(%d, \"%s\", \"%s\")...\n", rina_fd, dif, local_appl);
		rc = rina_register(rina_fd, dif, local_appl, 0);

		if (verbose) printf("  ...returns %d\n", rc);
		if (rc >= 0) {
			if (verbose) printf("  RINA FD = %d - swapping for %d\n", rina_fd, sockfd);
        		rc = (dup2(rina_fd, sockfd) > 0) ? 0 : -1;
        		close(rina_fd);
      		} else {
			if (verbose) perror("  rina_register");
		}
	} else {
		if (verbose) perror("  rina_open");
		rc = -1;
	}
	
	if (verbose) printf("...returns %d\n", rc);
	
	return rc;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	char * dif = getenv("RINA_DIF");
	char * local_appl = getenv("RINA_LOCAL_APPL");
	char * verbose = getenv("RINA_VERBOSE");
	int fd = 0;
	int rc = 0;

	if (verbose) printf("accept(%d, %p, %p)...\n", sockfd, addr, addrlen);
	
	if ((dif == NULL) || (local_appl == NULL)) {
		errno = EADDRNOTAVAIL;
		if (verbose)
			perror("   Local appl name or DIF name are NULL\n");
		return -1;
	}

	if (verbose) printf("  RINA_DIF=%s, RINA_LOCAL_APPL=%s => RINA interposer enabled!\n", dif, local_appl);
    		
	fd_set read_fds;
	FD_ZERO(&read_fds);
	FD_SET(sockfd, &read_fds);
    
	if (verbose) printf("  select(%d, %p, NULL, NULL, NULL)...\n", sockfd + 1, &read_fds);
    
	rc = select(sockfd + 1, &read_fds, NULL, NULL, NULL);
    
	if (verbose) printf("  returns %d\n", rc);
    	if (verbose) printf("  rina_flow_accept(%d, NULL, NULL, 0)...\n", sockfd);
    
	fd = rina_flow_accept(sockfd, NULL, NULL, 0);
    
	if (verbose) printf("  ...returns %d\n", fd);

	if (fd >= 0) {
      		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
      		addr_in->sin_family = AF_INET;
      		addr_in->sin_port = htons(1234);
      		inet_aton("127.0.0.1", &addr_in->sin_addr);
      		*addrlen = sizeof(struct sockaddr_in);
	} else {
      		if (verbose) perror("  rina_flow_accept");
    	}
  
	if (verbose) printf("...returns %d\n", fd);
  	
	return fd;
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
  	char* verbose = getenv("RINA_VERBOSE");
	int rc = 0;

	if (verbose) printf("getaddrinfo(%p, %p, %p, %p)...\n", node, service, hints, res);
  
	if (verbose) printf("...returns %d\n", rc);
  	
	return rc;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	char* verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("getsockname(%d, %p, %p)...\n", sockfd, addr, addrlen);

	return 0;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	char* verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("getpeername(%d, %p, %p)...\n", sockfd, addr, addrlen);

	return 0;
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
	char* verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("getsockopt(%d, %d, %d, %p, %p)...\n", sockfd,
			     level, optname, optval, optlen);

	return 0;
}

int setsockopt(int sockfd, int level, int optname,
		                      const void *optval, socklen_t optlen) {
	char* verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("setsockopt(%d, %d, %d, %p, %d)...\n", sockfd,
			     level, optname, optval, optlen);

	return 0;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
	char* verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("recv(%d, %p, %d, %d)...\n", sockfd, buf, len, flags);

	return 0;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		                        struct sockaddr *src_addr, socklen_t *addrlen) {
	char* verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("recvfrom(%d, %p, %d, %p, %p)...\n", sockfd,
				buf, len, flags, src_addr, addrlen);

	return 0;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
	char* verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("recvmsg(%d, %p, %d), ...\n", sockfd, 
			msg, flags);

	return 0;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
	char* verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("send(%d, %p, %d, %d),...\n", sockfd, buf,
				len, flags);

	return 0;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen){
	char* verbose = getenv("RINA_VERBOSE");

	if (verbose) printf("sendto(%d, %p, %d, %d, %p, %d),...\n", sockfd, 
				buf, len, flags, dest_addr, addrlen);

	return 0;
}


