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

#ifndef RINA_FAUX_SOCKETS_INTERNAL_H
#define RINA_FAUX_SOCKETS_INTERNAL_H

#include <rina/api.h>
#include <sys/types.h>

#define MAX_RINA_APP_NAME_SIZE 100

struct faux_socket {
	int domain;
	int type;
	int protocol;
	int sockfd;
	struct sockaddr * bind_addr;
	socklen_t bind_addrlen;
	char bind_app_name[MAX_RINA_APP_NAME_SIZE];
	struct sockaddr * peer_addr;
	socklen_t peer_addrlen;
	char peer_app_name[MAX_RINA_APP_NAME_SIZE];
};

/* Check if the socket domain, type and protocols are 
 * supported by the faux sockets API implementation */
int is_socket_supported(int domain, int type, int protocol);

/* Allocates a faux socket data structure and stores it in 
 * the faux sockets table */
int open_faux_socket(int domain, int type, int protocol, int sockfd);

/* Binds the faux socket to the provided address. It will later
 * be used to generate the local application name */
int bind_faux_socket(int sockfd, const struct sockaddr* addr, 
		     socklen_t addrlen);

/* Construct an application name from a sockaddr data structure */
int get_app_name_from_addr(int sockfd, const struct sockaddr* addr,
			   socklen_t addrlen, char * app_name);

/* Set the socket peer */
int set_faux_socket_peer(int sockfd, const struct sockaddr * addr,
			 socklen_t addrlen);

/* Populates a RINA flow spec based on the socket type */
int populate_rina_fspec(int sockfd, struct rina_flow_spec * fspec);

/* Copies the faux socket data to the provided data structure */
int get_faux_socket_data(int sockfd, struct faux_socket * fs);

/* Get the address to which this faux socket is bound to */
int get_faux_sockname(int sockfd, struct sockaddr* addr, 
		      socklen_t * addrlen);

/* Get the address of the peer to wich this fs is connected */
int get_faux_peername(int sockfd, struct sockaddr* addr, 
		      socklen_t * addrlen);

/* Removes the faux socket structure from the table and 
 * frees its memory */
int close_faux_socket(int sockfd);

/* Deallocates the memory allocated to the faux socket struct */
int free_faux_socket(struct faux_socket * fs);

/* Store a faux socket sockopt */
int store_faux_sockopt(int level, int optname, const void * optval, 
		       socklen_t len);

/* Retrieve the value of a faux socket sockopt */
int get_faux_sockopt_value(int optname, socklen_t * len);

/* ANSI C version of itoa, since it is not standard */
void itoa(int value, char* str, int base);

#endif /* RINA_FAUX_SOCKETS_INTERNAL_H */
