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

struct faux_socket {
	int domain;
	int type;
	int protocol;
	int sockfd;
};

/* Check if the socket domain, type and protocols are 
 * supported by the faux sockets API implementation */
int is_socket_supported(int domain, int type, int protocol);

/* Allocates a faux socket data structure and stores it in 
 * the faux sockets table */
int open_faux_socket(int domain, int type, int protocol, 
		     int sockfd, struct faux_socket ** fs);

/* Gets the faux socket structure associated to sockfd */
int get_faux_socket(int sockfd, struct faux_socket ** fs);

/* Populates a RINA flow spec based on the socket type */
int populate_rina_fspec(struct faux_socket * fs, 
			struct rina_flow_spec * fspec);

/* Removes the faux socket structure from the table and 
 * frees its memory */
int close_faux_socket(int sockfd);

#endif /* RINA_FAUX_SOCKETS_INTERNAL_H */
