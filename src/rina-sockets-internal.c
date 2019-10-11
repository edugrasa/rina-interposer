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
#include <stdlib.h>
#include <sys/socket.h>
#include "khash.h"
#include "rina-sockets-internal.h"

KHASH_MAP_INIT_INT(fauxs, struct faux_socket *)
struct faux_sockets_store {
	pthread_mutex_t mutex;
	khash_t(fauxs) * ht; /* Hash table to store faux sockets */
	int last_sockfd;
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

	/* Initialize Last sock fd */
	fs_store->last_sockfd = 0;

	return fs_store;
}

int open_faux_socket(int domain, int type, int protocol, struct faux_socket * fs) {
	struct faux_sockets_store * fss;
	khint_t k;
	int ret;

	fss = get_fs_store();
	if (!fss) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	/* TODO Check for supported socket families */

	fs = calloc(1, sizeof(struct faux_socket));
	if (!fs) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	fs->domain = domain;
	fs->type = type;
	fs->protocol = protocol;
	
	/* TODO Initialize RINA Flow spec based on socket type */
	switch(type) {
		case SOCK_STREAM:
			break;
		case SOCK_DGRAM:
			break;
		case SOCK_SEQPACKET:
			break;
		case SOCK_RDM:
			break;
		case SOCK_RAW: /* Not supported */
		default:
			errno = EINVAL;
			return -1;
	}

	pthread_mutex_lock(&fss->mutex);

	fss->last_sockfd++;
	fs->sockfd = fss->last_sockfd;
	fs->rinafd = 0;
	
	/* Insert faux socket into hash table */
	k = kh_put(fauxs, fss->ht, fs->sockfd, &ret);
	if (!ret) {
		/* TODO log error */
		kh_del(fauxs, fss->ht, fs->sockfd);
	}
	kh_value(fss->ht, k) = fs;

	pthread_mutex_unlock(&fss->mutex);

	return fs->sockfd;
}

int get_faux_socket(int sockfd, struct faux_socket * fs) {
	struct faux_sockets_store * fss;
	khint_t k;
	int ret;

	fss = get_fs_store();
	if (!fss) {
		/* TODO log error */
		errno = ENOMEM;
		return -1;
	}

	pthread_mutex_lock(&fss->mutex);

	/* Get faux socket from hash table */
	k = kh_get(fauxs, fss->ht, sockfd);
	if (k == kh_end(fss->ht)) {
		/* TODO log error */
		errno = EINVAL;
		ret = -1;
	} else {
		fs = kh_value(fss->ht, k);
		ret = 0;
	}

	pthread_mutex_unlock(&fss->mutex);

	return ret;
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
	if (fs) free(fs);

	return ret;
}
