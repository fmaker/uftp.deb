/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2011   Dennis A. Bush, Jr.   bush@tcnj.edu
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  Additional permission under GNU GPL version 3 section 7
 *
 *  If you modify this program, or any covered work, by linking or
 *  combining it with the OpenSSL project's OpenSSL library (or a
 *  modified version of that library), containing parts covered by the
 *  terms of the OpenSSL or SSLeay licenses, the copyright holder
 *  grants you additional permission to convey the resulting work.
 *  Corresponding Source for a non-source form of such a combination
 *  shall include the source code for the parts of OpenSSL used as well
 *  as that of the covered work.
 */

#include <string.h>
#include <errno.h>

#ifdef WINDOWS

#include <ws2tcpip.h>
#include <io.h>

#include "win_func.h"

#else  // if WINDOWS

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#endif

#include "uftp_common.h"
#include "heartbeat_send.h"

/**
 * Process an HB_RESP message
 */
void handle_hb_response(SOCKET s, const struct sockaddr_in *src,
                        const unsigned char *packet,
                        struct sockaddr_in hb_hosts[], int num_hosts,
                        int noname, RSA_key_t privkey)
{
    struct uftp_h *header;
    struct hb_resp_h *hbresp;
    struct hostent *hp;
    int hostidx;

    header = (struct uftp_h *)packet;
    hbresp = (struct hb_resp_h *)(packet + sizeof(struct uftp_h));

    if (!noname && (hp = gethostbyaddr((char *)&src->sin_addr,
                                       sizeof(struct in_addr), AF_INET))) {
        log(0, 0, "Received HB_RESP from %s (%s)",
                  hp->h_name, inet_ntoa(src->sin_addr));
    } else {
        log(0, 0, "Received HB_RESP from %s", inet_ntoa(src->sin_addr));
    }
    if (hbresp->authenticated == HB_AUTH_CHALLENGE) {
        log(0, 0, "Heartbeat authentication required");
        for (hostidx = 0; hostidx < num_hosts; hostidx++) {
            if ((src->sin_addr.s_addr == hb_hosts[hostidx].sin_addr.s_addr) &&
                    (src->sin_port == hb_hosts[hostidx].sin_port)) {
                send_auth_hb_request(s, hb_hosts[hostidx], ntohl(hbresp->nonce),
                                     privkey);
                break;
            }
        }
    } else if (hbresp->authenticated == HB_AUTH_FAILED) {
        log(0, 0, "Heartbeat authentication failed");
    } else if (hbresp->authenticated == HB_AUTH_OK) {
        log(0, 0, "Heartbeat authentication successful");
    }
}

/**
 * Sends an authenticated HB_REQ message to the given host.
 */
void send_auth_hb_request(SOCKET s, struct sockaddr_in hbhost, uint32_t nonce,
                          RSA_key_t privkey)
{
    unsigned char *packet, *keymod, *sig;
    struct uftp_h *header;
    struct hb_req_h *hbreq;
    uint8_t modulus[PUBKEY_LEN];
    uint32_t exponent, n_nonce;
    uint16_t modlen;
    unsigned int meslen, siglen;

    packet = calloc(sizeof(struct uftp_h) + sizeof(struct hb_req_h) +
                    (PUBKEY_LEN * 2) , 1);
    if (packet == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)packet;
    hbreq = (struct hb_req_h *)(packet + sizeof(struct uftp_h));
    keymod = (unsigned char *)hbreq + sizeof(struct hb_req_h);
    header->uftp_id = UFTP_VER_NUM;
    header->func = HB_REQ;
    hbreq->func = HB_REQ;

    if (!export_RSA_key(privkey, &exponent,
                        modulus, &modlen)) {
        log(0, 0, "Error exporting public key");
        free(packet);
        return;
    }

    n_nonce = htonl(nonce);
    hbreq->nonce = n_nonce;
    hbreq->keyexp = htonl(exponent);
    memcpy(keymod, modulus, modlen);
    hbreq->keylen = htons(modlen);
    sig = keymod + modlen;
    if (!create_RSA_sig(privkey, HASH_SHA1, (unsigned char *)&n_nonce,
                        sizeof(n_nonce), sig, &siglen) ||
                siglen > modlen) {
        log(0, 0, "Error signing nonce");
        free(packet);
        return;
    }
    hbreq->siglen = htons(siglen);
    meslen = sizeof(struct hb_req_h) + modlen + siglen;

    header->blsize = htons(meslen);
    meslen += sizeof(struct uftp_h);
    if (nb_sendto(s, packet, meslen, 0, (struct sockaddr *)&hbhost,
                  sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error sending HB_REQ");
    } else {
        log(0, 0, "Sent authenticated HB_REQ to %s:%d",
                  inet_ntoa(hbhost.sin_addr), ntohs(hbhost.sin_port));
    }
    free(packet);
}

/**
 * Sends an HB_REQ message to each host listed in the hb_host list
 */
void send_hb_request(SOCKET s, struct sockaddr_in hb_hosts[], int num_hosts,
                     struct timeval *next_hb_time, int hb_interval)
{
    unsigned char *packet;
    struct uftp_h *header;
    struct hb_req_h *hbreq;
    int meslen, i;

    packet = calloc(sizeof(struct uftp_h) + sizeof(struct hb_req_h), 1);
    if (packet == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)packet;
    hbreq = (struct hb_req_h *)(packet + sizeof(struct uftp_h));
    header->uftp_id = UFTP_VER_NUM;
    header->func = HB_REQ;
    hbreq->func = HB_REQ;

    for (i = 0; i < num_hosts; i++) {
        hbreq->nonce = 0;
        hbreq->keylen = 0;
        hbreq->siglen = 0;
        meslen = sizeof(struct hb_req_h);
        header->blsize = htons(meslen);
        meslen += sizeof(struct uftp_h);
        if (nb_sendto(s, packet, meslen, 0, (struct sockaddr *)&hb_hosts[i],
                      sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error sending HB_REQ");
        } else {
            log(0, 0, "Sent HB_REQ to %s:%d",
                      inet_ntoa(hb_hosts[i].sin_addr),
                      ntohs(hb_hosts[i].sin_port));
        }
    }
    free(packet);
    gettimeofday(next_hb_time, NULL);
    next_hb_time->tv_sec += hb_interval;
}

