/*
 * Faux Sockets API implementation for the RINA IPC API developed by H2020 
 * ARCFIRE
 *
 * Copyright (C) 2019-2020 Fundaciói2CAT
 * Author: Eduard Grasa <eduard.grasa@i2cat.net>
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "khash.h"
#include "rina-sockets-internal.h"

/**
 * 	
 * * Ansi C "itoa" based on Kernighan & Ritchie's "Ansi C":
 * 	 	
 * */
void strreverse(char* begin, char* end) {
	char aux;
	
	while(end>begin)
		aux=*end, *end--=*begin, *begin++=aux;		
}
	
void itoa(int value, char* str, int base) {	
	static char num[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	char* wstr=str;
	int sign;

	/* Validate base */ 	
	if (base<2 || base>35){ *wstr='\0'; return; } 				
	
	/* Take care of sign */ 						
	if ((sign=value) < 0) value = -value;								
	
	/* Conversion. Number is reversed */
	do *wstr++ = num[value%base]; while(value/=base);
	if(sign<0) *wstr++='-';
	*wstr='\0';
	
	/*Reverse string */ 																					
	strreverse(str,wstr-1);																						
}

KHASH_MAP_INIT_INT(fauxs, struct faux_socket *)
struct faux_sockets_store {
	pthread_mutex_t mutex;
	khash_t(fauxs) * ht; /* Hash table to store faux sockets */
	unsigned short next_port; /* Next available port number */
};

struct faux_sockets_store * fs_store = NULL;

struct faux_sockets_store * get_fs_store() {
	pthread_mutexattr_t attributes;

	if (fs_store) return fs_store;

	fs_store = calloc(1, sizeof(struct faux_sockets_store));
	if (!fs_store) {
		/* TODO log error */
	}

	/* Initialize pthred_mutex */
	pthread_mutexattr_init(&attributes);
	pthread_mutex_init(&fs_store->mutex, &attributes);
	pthread_mutexattr_destroy(&attributes);

	/* Initialize hash table */
	fs_store->ht = kh_init(fauxs);
	if (!fs_store->ht) {
		/* TODO log error */
	}

	/* Initialize next port */
	fs_store->next_port = 1;

	return fs_store;
}

int is_socket_supported(int domain, int type, int protocol) {
	if (domain != AF_INET && domain != AF_INET6) {
		/* TODO log error */
		errno = EINVAL;
		return -1;
	}

	if (type == SOCK_RAW) {
		/* TODO log error */
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int open_faux_socket(int domain, int type, int protocol, int sockfd) {
	struct faux_sockets_store * fss;
	struct faux_socket * fs;
	khint_t k;
	int ret;

	fss = get_fs_store();
	if (!fss) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	fs = calloc(1, sizeof(struct faux_socket));
	if (!fs) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	fs->domain = domain;
	fs->type = type;
	fs->protocol = protocol;
	fs->bind_addr = NULL;
	fs->bind_addrlen = 0;
	fs->peer_addr = NULL;
	fs->peer_addrlen = 0;

	pthread_mutex_lock(&fss->mutex);

	fs->sockfd = sockfd;
	
	/* Insert faux socket into hash table */
	k = kh_put(fauxs, fss->ht, fs->sockfd, &ret);
	if (!ret) {
		/* TODO log error */
		kh_del(fauxs, fss->ht, fs->sockfd);
	}
	kh_value(fss->ht, k) = fs;

	pthread_mutex_unlock(&fss->mutex);

	return 0;
}

int _get_faux_socket(int sockfd, struct faux_socket ** fs, 
		     struct faux_sockets_store * fss) {
	khint_t k;
	int ret;

	/* Get faux sockets from hash table */
	k = kh_get(fauxs, fss->ht, sockfd);
	if (k == kh_end(fss->ht)) {
		/* TODO log error */
		errno = EINVAL;
		ret = -1;
	} else {
		*fs = kh_value(fss->ht, k);
		ret = 0;
	}

	return ret;
}

int free_faux_socket(struct faux_socket * fs) {
	if (!fs) {
		errno = EINVAL;
		return -1;
	}

	if (fs->bind_addr) free(fs->bind_addr);
	if (fs->peer_addr) free(fs->peer_addr);

	free(fs);

	return 0;
}

void app_name_from_sockaddr_in(const struct sockaddr_in * in_addr,
			      char * app_name) {
	char buffer[20];
	
	itoa(ntohs(in_addr->sin_port), buffer, 10);
	strcpy(app_name, inet_ntoa(in_addr->sin_addr));
	strcat(app_name, "||");
	strcat(app_name, buffer);
	strcat(app_name, "|");
}

void app_name_from_sockaddr_in6(const struct sockaddr_in6 * in_addr,
				char * app_name) {
	char buffer[20];
	char abuffer[INET6_ADDRSTRLEN];
		
	itoa(ntohs(in_addr->sin6_port), buffer, 10);
	inet_ntop(AF_INET6, in_addr, abuffer, INET6_ADDRSTRLEN);
	strcpy(app_name, abuffer);
	strcat(app_name, "||");
	strcat(app_name, buffer);
	strcat(app_name, "|");
}

int bind_to_ipv4_address(struct faux_socket * fs, const struct sockaddr * addr,
			 socklen_t addrlen) {
	struct sockaddr_in * in_addr;
	struct sockaddr_in * in_fs_addr;

	if (addrlen != sizeof(struct sockaddr_in)) {
		/* TODO log error */
		errno = EINVAL;
		return -1;
	}

	in_addr = (struct sockaddr_in *)addr;
 	
	fs->bind_addr = calloc(1, sizeof(struct sockaddr_in));
	if (!fs->bind_addr) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	in_fs_addr = (struct sockaddr_in *)fs->bind_addr;

	memset(in_fs_addr, 0, sizeof(struct sockaddr_in));

	in_fs_addr->sin_family = in_addr->sin_family;
	in_fs_addr->sin_port = in_addr->sin_port;
	in_fs_addr->sin_addr.s_addr = in_addr->sin_addr.s_addr;

	fs->bind_addrlen = addrlen;
	
	/* Create local application name */
	app_name_from_sockaddr_in(in_fs_addr, fs->bind_app_name);

	return 0;
}

int bind_to_ipv6_address(struct faux_socket * fs, const struct sockaddr * addr,
			 socklen_t addrlen) {
	struct sockaddr_in6 * in_addr;
	struct sockaddr_in6 * in_fs_addr;
	
	if (addrlen != sizeof(struct sockaddr_in6)) {
		/* TODO log error */
		errno = EINVAL;
		return -1;
	}

	in_addr = (struct sockaddr_in6 *)addr;

	fs->bind_addr = calloc(1, sizeof(struct sockaddr_in6));
	if (!fs->bind_addr) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	in_fs_addr = (struct sockaddr_in6 *)fs->bind_addr;

	memset(in_fs_addr, 0, sizeof(struct sockaddr_in6));

	in_fs_addr->sin6_family = in_addr->sin6_family;
	in_fs_addr->sin6_port = in_addr->sin6_port;
	in_fs_addr->sin6_flowinfo = in_addr->sin6_flowinfo;
	in_fs_addr->sin6_scope_id = in_addr->sin6_scope_id;
	memcpy(in_fs_addr->sin6_addr.s6_addr, in_addr->sin6_addr.s6_addr, 16);

	fs->bind_addrlen = addrlen;

	/* Create local application name */
	app_name_from_sockaddr_in6(in_fs_addr, fs->bind_app_name);

	return 0;
}

int bind_faux_socket(int sockfd, const struct sockaddr * addr, 
		     socklen_t addrlen) {
	struct faux_sockets_store * fss;
	struct faux_socket * fs;
	int ret;

	fss = get_fs_store();
	if (!fss) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	pthread_mutex_lock(&fss->mutex);
	
	ret = _get_faux_socket(sockfd, &fs, fss);
	if (ret == 0) {
		switch(fs->domain) {
			case AF_INET:
				ret = bind_to_ipv4_address(fs, addr, addrlen);
				break;
			case AF_INET6:
				ret = bind_to_ipv6_address(fs, addr, addrlen);
				break;
			default:
				/* TODO log error */
				errno = EINVAL;
				ret = -1;
		}
	}

	pthread_mutex_unlock(&fss->mutex);

	return ret;
}

int get_app_name_from_ipv4_addr(const struct sockaddr* addr,
			   	socklen_t addrlen, char * app_name) {
	struct sockaddr_in * in_addr;

	if (addrlen != sizeof(struct sockaddr_in)) {
		/* TODO log error */
		errno = EINVAL;
		return -1;
	}

	in_addr = (struct sockaddr_in *)addr;

	app_name_from_sockaddr_in(in_addr, app_name);

	return 0;
}

int get_app_name_from_ipv6_addr(const struct sockaddr* addr,
				socklen_t addrlen, char * app_name) {
	struct sockaddr_in6 * in_addr;

	if (addrlen != sizeof(struct sockaddr_in6)) {
		/* TODO log error */
		errno = EINVAL;
		return -1;
	}

	in_addr = (struct sockaddr_in6 *)addr;

	app_name_from_sockaddr_in6(in_addr, app_name);

	return 0;
}

int get_app_name_from_addr(int sockfd, const struct sockaddr* addr,
			   socklen_t addrlen, char * app_name) {
	struct faux_sockets_store * fss;
	struct faux_socket * fs;
	int ret;

	fss = get_fs_store();
	if (!fss) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	pthread_mutex_lock(&fss->mutex);

	ret = _get_faux_socket(sockfd, &fs, fss);
	if (ret == 0) {
		switch(fs->domain) {
			case AF_INET:
				ret = get_app_name_from_ipv4_addr(addr, addrlen,
								  app_name);
				break;
			case AF_INET6:
				ret = get_app_name_from_ipv6_addr(addr, addrlen,
								  app_name);
				break;
			default:
				/* TODO log error */
				errno = EINVAL;
				ret = -1;
		}
	}

	pthread_mutex_unlock(&fss->mutex);

	return ret;
}

int get_ipv4_sockname(struct faux_socket * fs, struct sockaddr * addr, 
		      socklen_t * addrlen) {
	struct sockaddr_in * in_addr;
	struct sockaddr_in * in_fs_addr;

	/* Don't allow different addrlen for the moment */
	if (*addrlen < sizeof(struct sockaddr_in)) {
		/* TODO log error */
		errno = EINVAL;
		return -1;
	}

	in_addr = (struct sockaddr_in *)addr;
	memset(in_addr, 0, sizeof(struct sockaddr_in));
	in_addr->sin_family = AF_INET;

	*addrlen = sizeof(struct sockaddr_in);

	/* The socket is not bound to any address */
	if (!fs->bind_addr) {
		return 0;
	}

	in_fs_addr = (struct sockaddr_in *)fs->bind_addr;
	in_addr->sin_port = in_fs_addr->sin_port;
	in_addr->sin_addr.s_addr = in_fs_addr->sin_addr.s_addr;

	return 0;
}

int get_ipv6_sockname(struct faux_socket * fs, struct sockaddr * addr,
		      socklen_t * addrlen) {
	struct sockaddr_in6 * in_addr;
	struct sockaddr_in6 * in_fs_addr;

	/* Don't allow different addrlen for the moment */
	if (*addrlen < sizeof(struct sockaddr_in6)) {
		/* TODO log error*/
		errno = EINVAL;
		perror("   get_ipv6_sockname: addrlen too small: ");
		return -1;
	}

	in_addr = (struct sockaddr_in6 *)addr;
	memset(in_addr, 0, sizeof(struct sockaddr_in6));
	in_addr->sin6_family = AF_INET6;

	*addrlen = sizeof(struct sockaddr_in6);

	/* The socket is not bound to any address */
	if (!fs->bind_addr) {
		return 0;
	}

	in_fs_addr = (struct sockaddr_in6 *)fs->bind_addr;
	in_addr->sin6_port = in_fs_addr->sin6_port;
	in_addr->sin6_flowinfo = in_fs_addr->sin6_flowinfo;
	in_addr->sin6_scope_id = in_fs_addr->sin6_scope_id;
	memcpy(in_addr->sin6_addr.s6_addr, in_fs_addr->sin6_addr.s6_addr, 16);

	return 0;
}

int get_faux_sockname(int sockfd, struct sockaddr* addr, 
		      socklen_t * addrlen) {
	struct faux_sockets_store * fss;
	struct faux_socket * fs;
	int ret;

	fss = get_fs_store();
	if (!fss) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	pthread_mutex_lock(&fss->mutex);

	ret = _get_faux_socket(sockfd, &fs, fss);
	if (ret == 0 && fs->bind_addr) {
		switch(fs->domain) {
			case AF_INET:
				ret = get_ipv4_sockname(fs, addr, addrlen);
				break;
			case AF_INET6:
				ret = get_ipv6_sockname(fs, addr, addrlen);
				break;
			default:
				/* TODO log error */
				errno = EBADF;
				perror("   get_faux_sockname: unknown domain: ");
				ret = -1;
		}
	}

	pthread_mutex_unlock(&fss->mutex);

	return ret;
}

int get_faux_socket_data(int sockfd, struct faux_socket * fs) {
	struct faux_sockets_store * fss;
	struct faux_socket * orig_fs;
	int ret;

	fss = get_fs_store();
	if (!fss) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	pthread_mutex_lock(&fss->mutex);

	ret = _get_faux_socket(sockfd, &orig_fs, fss);
	if (ret == 0) {
		fs->domain = orig_fs->domain;
		fs->type = orig_fs->type;
		fs->protocol = orig_fs->protocol;
		fs->sockfd = orig_fs->sockfd;
		fs->bind_addrlen = orig_fs->bind_addrlen;
		fs->bind_addr = orig_fs->bind_addr;
		strcpy(fs->bind_app_name, orig_fs->bind_app_name);
	}

	pthread_mutex_unlock(&fss->mutex);

	return ret;
}

int populate_rina_fspec(int sockfd, struct rina_flow_spec * fspec) {
	struct faux_sockets_store * fss;
	struct faux_socket * fs;
	int ret;
	int type;

	fss = get_fs_store();
	if (!fss) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	pthread_mutex_lock(&fss->mutex);

	ret = _get_faux_socket(sockfd, &fs, fss);
	if (ret == 0) {
		type = fs->type;
	} else {
		type = -1;
	}

	pthread_mutex_unlock(&fss->mutex);

	if (type == -1) return ret;

	fspec->version = 1;

	switch(type) {
		case SOCK_STREAM:
			fspec->max_sdu_gap = 0;
			fspec->max_loss = 0;
			fspec->in_order_delivery = 1;
			fspec->msg_boundaries = 0;
			break;
		case SOCK_DGRAM:
			fspec->max_sdu_gap = 10000;
			fspec->max_loss = 10000;
			fspec->in_order_delivery = 0;
			fspec->msg_boundaries = 1;
			break;
		case SOCK_SEQPACKET:
			fspec->max_sdu_gap = 0;
			fspec->max_loss = 0;
			fspec->in_order_delivery = 1;
			fspec->msg_boundaries = 1;
			break;
		case SOCK_RDM:
			fspec->max_sdu_gap = 0;
			fspec->max_loss = 0;
			fspec->in_order_delivery = 0;
			fspec->msg_boundaries = 1;
			break;
		default:
			/* Not supported type */
			errno = EINVAL;
			return -1;
	}

	return 0;
}

int close_faux_socket(int sockfd) {
	struct faux_sockets_store * fss;
	struct faux_socket * fs;
	khint_t k;
	int ret;
	
	fss = get_fs_store();
	if (!fss) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	pthread_mutex_lock(&fss->mutex);

	/* Get faux socket from hash table and remove it*/
	k = kh_get(fauxs, fss->ht, sockfd);
	if (k == kh_end(fss->ht)) {
		/* TODO log error */
		errno = EINVAL;
		ret = -1;
		fs = NULL;
	} else {
		fs = kh_value(fss->ht, k);
		kh_del(fauxs, fss->ht, k);
		ret = 0;
	}

	pthread_mutex_unlock(&fss->mutex);

	/* Destroy faux socket if we found it */
	free_faux_socket(fs);

	return ret;
}
