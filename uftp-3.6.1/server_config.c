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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef WINDOWS

#include <io.h>
#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_config.h"

/**
 * Global command line values and sockets
 */
SOCKET sock;
struct sockaddr_in listen_dest, receive_dest;
int weight, min_time, max_rate, rate, port, rcvbuf, packet_wait;
int noname, unicast, client_auth, quit_on_error, dscp, follow_links;
int save_fail, restart_groupid, sync_mode, sync_preview, dest_is_dir;
int announce_time, status_time;
int announce_int, status_int, register_int, done_int;
unsigned char ttl;
char pub_multi[IPSTR_LEN], priv_multi[IPSTR_LEN], destfname[MAXPATHNAME];
char logfile[MAXPATHNAME], keyfile[MAXPATHNAME], cc_config[MAXPATHNAME];
char filelist[MAXFILES][MAXPATHNAME], exclude[MAXEXCLUDE][MAXPATHNAME];
char basedir[MAXDIR][MAXDIRNAME];
struct iflist ifl[MAX_INTERFACES];
int keytype, hashtype, sigtype, newkeylen;
int mtu, blocksize, encpayloadsize, payloadsize;
int ifl_len, destcount, filecount, excludecount, basedircount, cc_count;
struct cc_config_t cc_list[MAXCC];
struct in_addr out_addr;
struct destinfo_t destlist[MAXDEST];

/**
 * Encryption variables
 */
RSA_key_t privkey;
unsigned char rand1[RAND_LEN], groupmaster[MASTER_LEN];
uint8_t groupsalt[MAXIV], groupkey[MAXKEY], grouphmackey[HMAC_LEN];
int ivlen, keylen, hmaclen, rsalen, sys_keys;

extern char *optarg;
extern int optind;

/**
 * Add a destination or proxy to the list as specified by -H or -j
 */
void add_dest_by_name(const char *destname, const char *fingerprint, int proxy)
{
    struct hostent *hp;
    struct in_addr *addr;

    if (destcount == MAXDEST) {
        fprintf(stderr,"Exceeded maximum destination count\n");
        exit(1);
    }
    if (inet_addr(destname) == INADDR_NONE) {
        if ((hp = gethostbyname(destname)) == NULL) {
            uint32_t uid = strtol(destname, NULL, 16);
            if ((uid > 0xffffff) || (uid <= 0)) {
                fprintf(stderr, "Invalid host name / UID\n");
                exit(1);
            }
            destlist[destcount].addr.s_addr = htonl(uid);
            strncpy(destlist[destcount].name, destname,
                    sizeof(destlist[destcount].name));
            destlist[destcount].name[sizeof(destlist[destcount].name)-1]='\x0';
            destlist[destcount].proxyidx = -1;
            destlist[destcount].clientcnt = proxy ? 0 : -1;
            destlist[destcount].has_fingerprint =
                    parse_fingerprint(destlist[destcount].keyfingerprint,
                                      fingerprint);
            destcount++;
        } else {
            addr = (struct in_addr *)hp->h_addr_list[0];
            destlist[destcount].addr = *addr;
            strncpy(destlist[destcount].name, destname,
                    sizeof(destlist[destcount].name));
            destlist[destcount].name[sizeof(destlist[destcount].name)-1]='\x0';
            destlist[destcount].proxyidx = -1;
            destlist[destcount].clientcnt = proxy ? 0 : -1;
            destlist[destcount].has_fingerprint =
                    parse_fingerprint(destlist[destcount].keyfingerprint,
                                      fingerprint);
            destcount++;
        }
    } else {
        destlist[destcount].addr.s_addr = inet_addr(destname);
        strncpy(destlist[destcount].name, destname,
                sizeof(destlist[destcount].name));
        destlist[destcount].name[sizeof(destlist[destcount].name)-1] = '\x0';
        destlist[destcount].proxyidx = -1;
        destlist[destcount].clientcnt = proxy ? 0 : -1;
        destlist[destcount].has_fingerprint =
                parse_fingerprint(destlist[destcount].keyfingerprint,
                                  fingerprint);
        destcount++;
    }
}

/**
 * Set defaults for all command line arguments
 */
void set_defaults()
{
    memset(destlist, 0, sizeof(destlist));
    memset(filelist, 0, sizeof(filelist));
    memset(exclude, 0, sizeof(exclude));
    memset(destfname, 0, sizeof(destfname));
    memset(cc_config, 0, sizeof(cc_config));
    destcount = 0;
    port = DEF_PORT;
    rate = DEF_RATE;
    max_rate = 0;
    weight = DEF_WEIGHT;
    min_time = DEF_MIN_TIME;
    out_addr.s_addr = INADDR_NONE;
    ttl = DEF_TTL;
    dscp = DEF_DSCP;
    mtu = DEF_MTU;
    log_level = DEF_LOG_LEVEL;
    unicast = DEF_UNICAST;
    noname = DEF_NONAME;
    rcvbuf = 0;
    memset(keyfile, 0, sizeof(keyfile));
    announce_time = DEF_ANNOUNCE_TIME;
    status_time = DEF_STATUS_TIME;
    announce_int = DEF_ANNOUNCE_INTERVAL;
    status_int = DEF_STATUS_INTERVAL;
    register_int = DEF_REGISTER_INTERVAL;
    done_int = DEF_DONE_INTERVAL;
    client_auth = 0;
    quit_on_error = 0;
    save_fail = 0;
    restart_groupid = 0;
    keytype = DEF_KEYTYPE;
    hashtype = DEF_HASHTYPE;
    sigtype = DEF_SIGTYPE;
    strncpy(pub_multi, DEF_PUB_MULTI, sizeof(pub_multi)-1);
    pub_multi[sizeof(pub_multi)-1] = '\x0';
    strncpy(priv_multi, DEF_PRIV_MULTI, sizeof(priv_multi)-1);
    priv_multi[sizeof(priv_multi)-1] = '\x0';
    strncpy(logfile, "", sizeof(logfile)-1);
    logfile[sizeof(logfile)-1] = '\x0';
    filecount = 0;
    excludecount = 0;
    basedircount = 0;
    newkeylen = 0;
    follow_links = 0;
    showtime = 0;
    sys_keys = 0;
    sync_mode = 0;
    sync_preview = 0;
    cc_count = 0;
    dest_is_dir = 0;
}

/**
 * Reads in the contents of the restart file.
 * Contains a server_restart_t header, followed by
 * one or more server_restart_host_t entries.
 */
void read_restart_file(const char *restart_name)
{
    struct server_restart_t header;
    struct server_restart_host_t host;
    int fd, i, rval;

    if ((fd = open(restart_name, OPENREAD)) == -1) {
        syserror(0, 0, "Failed to open restart file");
        exit(1);
    }

    if (file_read(fd, &header, sizeof(header), 0) == -1) {
        log0(0, 0, "Failed to read header from restart file");
        exit(1);
    }
    restart_groupid = header.group_id;

    if ((header.filecount > MAXFILES) || (header.filecount <= 0)) {
        log0(0, 0, "Too many files listed in restart file");
        exit(1);
    }
    for (i = 0; i < header.filecount; i++) {
        if (file_read(fd, filelist[i], sizeof(filelist[i]), 0) == -1) {
            log0(0, 0, "Failed to read filename from restart file");
            exit(1);
        }
    }
    filecount = header.filecount;

    while ((rval = file_read(fd, &host, sizeof(host), 1)) != 0) {
        if (rval == -1) {
            log0(0, 0, "Failed to read host from restart file");
            exit(1);
        }
        memcpy(destlist[destcount].name, host.name, sizeof(host.name));
        destlist[destcount].addr = host.addr;
        destlist[destcount].proxyidx = -1;
        destlist[destcount].clientcnt = host.is_proxy ? 0 : -1;
        destlist[destcount].has_fingerprint = host.has_fingerprint;
        if (host.has_fingerprint) {
            memcpy(destlist[destcount].keyfingerprint, host.keyfingerprint,
                   sizeof(destlist[destcount].keyfingerprint));
        }
        destcount++;
    }
}

/**
 * Reads in the congestion control config file.
 * Each line contains a percentage (0-100) followed by a scaling factor
 * or the string "max" followed by the maximum transmission rate in Kbps
 * Sample:
 * max;10000
 * 0;1.3
 * 5;1.1
 * 10;0.9
 * 25;0.7
 * 50;0.4
 *
 * Returns 1 on success, 0 on fail.
 */
int read_cc_config(const char *filename)
{
    FILE *cc_file;
    char line[100], *p;
    int last_percentage, percentage;
    double scaling_factor;
    struct cc_config_t tmp_cc_list[MAXCC];
    int tmp_cc_count, tmp_max_rate;

    if ((cc_file = fopen(filename, "rt")) == NULL) {
        log0(0, 0, "Couldn't open congestion control file %s: %s\n",
                cc_config, strerror(errno));
        return 0;
    }
    tmp_cc_count = 0;
    tmp_max_rate = 0;
    last_percentage = 0;
    while (fgets(line, sizeof(line), cc_file)) {
        while ((strlen(line) > 0) && ((line[strlen(line)-1] == '\r') ||
               (line[strlen(line)-1] == '\n'))) {
            line[strlen(line)-1] = '\x0';
        }
        if (strlen(line) == 0) continue;
        p = strtok(line, ";");
        if (p == NULL) {
            log0(0, 0, "Error reading congestion control entry\n");
            return 0;
        }
        if (!strcmp(p, "max")) {
            if (tmp_max_rate) {
                log0(0, 0, "Cannot have multiple entries for max rate\n");
                return 0;
            }
            p = strtok(NULL, ";");
            if (p == NULL) {
                log0(0, 0, "Error reading congestion control entry\n");
                return 0;
            }
            tmp_max_rate = strtol(p, NULL, 10);
            if (tmp_max_rate <= 0) {
                log0(0, 0, "Invalid max rate in congestion control\n");
                return 0;
            }
            continue;
        }
        percentage = strtol(p, NULL, 10);
        if ((percentage < 0) || percentage > 100) {
            log0(0, 0, "Invalid percentage in congestion control entry\n");
            return 0;
        }
        if (percentage < last_percentage) {
            log0(0, 0, "Congestion control entries must be in ascending "
                       "order by percentage\n");
            return 0;
        }
        p = strtok(NULL, ";");
        if (p == NULL) {
            log0(0, 0, "Error reading congestion control entry\n");
            return 0;
        }
        errno = 0;
        scaling_factor = strtod(p, NULL);
        if (errno) {
            log0(0, 0, "Error reading congestion control entry: %s\n",
                    strerror(errno)); 
            return 0;
        }
        if (scaling_factor <= 0) {
            log0(0, 0, "Invalid scaling factor in congestion control entry\n");
            return 0;
        }
        last_percentage = percentage;
        tmp_cc_list[tmp_cc_count].percentage = percentage;
        tmp_cc_list[tmp_cc_count].scaling_factor = scaling_factor;
        tmp_cc_count++;
    }
    fclose(cc_file);

    // Make sure we have a top end entry, make scaling same as last specified
    tmp_cc_list[tmp_cc_count].percentage = 100;
    tmp_cc_list[tmp_cc_count].scaling_factor =
            tmp_cc_list[tmp_cc_count - 1].scaling_factor;
    tmp_cc_count++;

    // Config successfully read in, copy to real list
    for (cc_count = 0; cc_count < tmp_cc_count; cc_count++) {
        cc_list[cc_count] = tmp_cc_list[cc_count];
    }
    if (tmp_max_rate) {
        max_rate = tmp_max_rate;
    } else {
        max_rate = rate;
    }
    return 1;
}

/**
 * Set argument defaults, read and validate command line options
 */
void process_args(int argc, char *argv[])
{
    int c, i, listidx, read_restart;
    long tmpval;
    struct hostent *hp;
    struct in_addr *paddr, addr;
    char line[1000], *dest, *destname, filename[MAXPATHNAME], *fingerprint, *p;
    FILE *destfile, *excludefile, *listfile;
    const char opts[] = 
        "Ux:R:W:m:nL:B:Y:h:w:ck:K:lTA:S:a:s:r:d:"
        "b:t:Q:zZI:p:j:qfyH:F:X:M:P:C:D:oE:i:";

    set_defaults();
    read_restart = 0;

    // read lettered arguments
    while ((c = getopt(argc, argv, opts)) != EOF) {
        switch (c) {
        case 'U':
            unicast = 1;
            break;
        case 'x':
            log_level = atoi(optarg);
            if (log_level < 0) {
                fprintf(stderr,"Invalid log level\n");
                exit(1);
            }
            break;
        case 'R':
            rate = atoi(optarg);
            if ((rate <= 0) && (rate != -1)) {
                fprintf(stderr,"Invalid rate\n");
                exit(1);
            }
            if ((rate == -1) && (cc_count > 0)) {
                fprintf(stderr,"Can't specify -R -1 with -C\n");
                exit(1);
            }
            break;
        case 'W':
            weight = atoi(optarg);
            if ((weight < 110) || (weight > 10000)) {
                fprintf(stderr, "Invalid weight\n");
                exit(1);
            }
            break;
        case 'm':
            min_time = atoi(optarg);
            if ((min_time <= 0) || (min_time > 3600)) {
                fprintf(stderr, "Invalid min time\n");
                exit(1);
            }
            break;
        case 'n':
            noname = 1;
            break;
        case 'L':
            strncpy(logfile, optarg, sizeof(logfile)-1);
            logfile[sizeof(logfile)-1] = '\x0';
            break;
        case 'B':
            rcvbuf = atoi(optarg);
            if ((rcvbuf < 65536) || (rcvbuf > 104857600)) {
                fprintf(stderr, "Invalid receive buffer size\n");
                exit(1);
            }
            break;
        case 'Y':
            if (!strcmp(optarg, "none")) {
                keytype = KEY_NONE;
            } else if (!strcmp(optarg, "des")) {
                keytype = KEY_DES;
            } else if (!strcmp(optarg, "3des")) {
                keytype = KEY_DES_EDE3;
            } else if (!strcmp(optarg, "aes128")) {
                keytype = KEY_AES128;
            } else if (!strcmp(optarg, "aes256")) {
                keytype = KEY_AES256;
            } else {
                fprintf(stderr, "Invalid keytype\n");
                exit(1);
            }
            if (keytype != KEY_NONE && !cipher_supported(keytype)) {
                fprintf(stderr, "Keytype not supported\n");
                exit(1);
            }
            break;
        case 'h':
            if (!strcmp(optarg, "sha1")) {
                hashtype = HASH_SHA1;
            } else if (!strcmp(optarg, "sha256")) {
                hashtype = HASH_SHA256;
            } else {
                fprintf(stderr, "Invalid hashtype\n");
                exit(1);
            }
            if (!hash_supported(hashtype)) {
                fprintf(stderr, "Hashtype not supported\n");
                exit(1);
            }
            break;
        case 'w':
            if (!strcmp(optarg, "hmac")) {
                sigtype = SIG_HMAC;
            } else if (!strcmp(optarg, "rsa")) {
                sigtype = SIG_RSA;
            } else {
                fprintf(stderr, "Invalid sigtype\n");
                exit(1);
            }
            break;
        case 'c':
            client_auth = 1;
            break;
        case 'k':
            strncpy(keyfile, optarg, sizeof(keyfile)-1);
            keyfile[sizeof(keyfile)-1] = '\x0';
            break;
        case 'K':
            newkeylen = atoi(optarg);
            if ((newkeylen < 512) || (newkeylen > 2048)) {
                fprintf(stderr, "Invalid new key length\n");
                exit(1);
            }
            break;
        case 'l':
            follow_links = 1;
            break;
        case 'T':
            showtime = 1;
            break;
        case 'A':
            announce_time = atoi(optarg); 
            if ((announce_time < 1) || (announce_time > 240)) {
                fprintf(stderr, "Invalid announce time\n");
                exit(1);
            }
            break;
        case 'S':
            status_time = atoi(optarg); 
            if ((status_time < 1) || (status_time > 240)) {
                fprintf(stderr, "Invalid status time\n");
                exit(1);
            }
            break;
        case 'a':
            announce_int = atoi(optarg); 
            if ((announce_int < 500) || (announce_int > 20000)) {
                fprintf(stderr, "Invalid announce interval\n");
                exit(1);
            }
            break;
        case 's':
            status_int = atoi(optarg); 
            if ((status_int < 500) || (status_int > 20000)) {
                fprintf(stderr, "Invalid status interval\n");
                exit(1);
            }
            break;
        case 'r':
            register_int = atoi(optarg); 
            if ((register_int < 500) || (register_int > 60000)) {
                fprintf(stderr, "Invalid register interval\n");
                exit(1);
            }
            break;
        case 'd':
            done_int = atoi(optarg); 
            if ((done_int < 500) || (done_int > 60000)) {
                fprintf(stderr, "Invalid done interval\n");
                exit(1);
            }
            break;
        case 'b':
            mtu = atoi(optarg); 
            if ((mtu < 576) || (mtu > 9000)) {
                fprintf(stderr, "Invalid mtu\n");
                exit(1);
            }
            break;
        case 't':
            tmpval = atoi(optarg);
            if ((tmpval <= 0) || (tmpval > 255)) {
                fprintf(stderr, "Invalid ttl\n");
                exit(1);
            }
            ttl = (char)tmpval;
            break;
        case 'Q':
            tmpval = strtol(optarg, NULL, 0);
            if ((tmpval < 0) || (tmpval > 63)) {
                fprintf(stderr, "Invalid dscp\n");
                exit(1);
            }
            dscp = (tmpval & 0xFF) << 2; 
            break;
        case 'I':
            if ((listidx = getifbyname(optarg, ifl, ifl_len)) != -1) {
                out_addr = ifl[listidx].addr;
                break;
            }
            if (inet_addr(optarg) == INADDR_NONE) {
                if ((hp = gethostbyname(optarg)) == NULL) {
                    fprintf(stderr, "Invalid host name: %s\n", optarg);
                    exit(1);
                } else {
                    paddr = (struct in_addr *)hp->h_addr_list[0];
                }
            } else {
                addr.s_addr = inet_addr(optarg);
                paddr = &addr;
            }
            if ((listidx = getifbyaddr(*paddr, ifl, ifl_len)) != -1) {
                out_addr = ifl[listidx].addr;
            } else {
                fprintf(stderr, "Interface %s not found\n", optarg);
                exit(1);
            }
            break;
        case 'z':
            sync_mode = 1;
            break;
        case 'Z':
            sync_preview = 1;
            sync_mode = 1;
            break;
        case 'p':
            port = atoi(optarg);
            if (port == 0) {
                fprintf(stderr, "Invalid port\n");
                exit(1);
            }
            break;
        case 'j':
            if (read_restart) {
                fprintf(stderr,"Can't specify both -j and -F\n");
                exit(1);
            }
            if ((destfile = fopen(optarg, "rt")) == NULL) {
                fprintf(stderr,"Couldn't open proxy list %s: %s\n",
                        optarg, strerror(errno));
                exit(1);
            }
            while (fgets(line, sizeof(line), destfile)) {
                while ((strlen(line) > 0) && ((line[strlen(line)-1] == '\r') ||
                       (line[strlen(line)-1] == '\n'))) {
                    line[strlen(line)-1] = '\x0';
                }
                destname = strtok(line, " \t");
                if (!destname) continue;
                if (destname[0] == '#') continue;
                if (strlen(destname) > DESTNAME_LEN) {
                    fprintf(stderr, "Proxylist: name too long\n");
                    exit(1);
                }
                fingerprint = strtok(NULL, " \t");
                add_dest_by_name(destname, fingerprint, 1);
            }
            if (!feof(destfile) && ferror(destfile)) {
                perror("Failed to read from proxylist file");
                exit(1);
            }
            fclose(destfile);
            break;
        case 'q':
            quit_on_error = 1;
            break;
        case 'f':
            save_fail = 1;
            break;
        case 'y':
            sys_keys = 1;
            break;
        case 'H':
            if (read_restart) {
                fprintf(stderr,"Can't specify both -H and -F\n");
                exit(1);
            }
            if (optarg[0] == '@') {
                dest = &optarg[1];
                if ((destfile = fopen(dest, "rt")) == NULL) {
                    fprintf(stderr,"Couldn't open destination list %s: %s\n",
                            dest, strerror(errno));
                    exit(1);
                }
                while (fgets(line, sizeof(line), destfile)) {
                    while ((strlen(line) > 0) &&
                           ((line[strlen(line)-1] == '\r') ||
                            (line[strlen(line)-1] == '\n'))) {
                        line[strlen(line)-1] = '\x0';
                    }
                    destname = strtok(line, " \t");
                    if (!destname) continue;
                    if (destname[0] == '#') continue;
                    if (strlen(destname) > DESTNAME_LEN) {
                        fprintf(stderr, "Hostlist: name too long\n");
                        exit(1);
                    }
                    fingerprint = strtok(NULL, " \t");
                    add_dest_by_name(destname, fingerprint, 0);
                }
                if (!feof(destfile) && ferror(destfile)) {
                    perror("Failed to read from hostlist file");
                    exit(1);
                }
                fclose(destfile);
            } else {
                dest = strtok(optarg, ",");
                while (dest != NULL) {
                    add_dest_by_name(dest, NULL, 0);
                    dest = strtok(NULL, ",");
                }
            }
            break;
        case 'F':
            if (destcount != 0) {
                fprintf(stderr,"Can't specify both -H and -F\n");
                exit(1);
            }
            read_restart = 1;
            save_fail = 1;
            read_restart_file(optarg);
            break;
        case 'X':
            if ((excludefile = fopen(optarg, "rt")) == NULL) {
                fprintf(stderr,"Couldn't open exclude list %s: %s\n",
                        optarg, strerror(errno));
                exit(1);
            }
            while (fgets(filename, sizeof(filename), excludefile)) {
                while ((strlen(filename) > 0) &&
                       ((filename[strlen(filename)-1] == '\r') ||
                        (filename[strlen(filename)-1] == '\n'))) {
                    filename[strlen(filename)-1] = '\x0';
                }
                if (strlen(filename) == 0) continue;
                if (excludecount == MAXEXCLUDE) {
                    fprintf(stderr,"Exceeded maximum exclude file count\n");
                    exit(1);
                }
                strncpy(exclude[excludecount], filename, sizeof(exclude[0]));
                exclude[excludecount][sizeof(exclude[0])-1] = '\x0';
                excludecount++;
            }
            if (!feof(excludefile) && ferror(excludefile)) {
                perror("Failed to read from exclude file");
                exit(1);
            }
            fclose(excludefile);
            break;
        case 'M':
            strncpy(pub_multi, optarg, sizeof(pub_multi)-1);
            pub_multi[sizeof(pub_multi)-1] = '\x0';
            break;
        case 'P':
            strncpy(priv_multi, optarg, sizeof(priv_multi)-1);
            priv_multi[sizeof(priv_multi)-1] = '\x0';
            break;
        case 'C':
            if (rate == -1) {
                fprintf(stderr,"Can't specify -C with -R -1\n");
                exit(1);
            }
            strncpy(cc_config, optarg, sizeof(cc_config)-1);
            cc_config[sizeof(cc_config)-1] = '\x0';
            if (!read_cc_config(cc_config)) {
                fprintf(stderr,"Error loading congestion control config\n");
                exit(1);
            }
            break;
        case 'D':
            strncpy(destfname, optarg, sizeof(destfname)-1);
            destfname[sizeof(destfname)-1] = '\x0';
            while (destfname[strlen(destfname)-1] == PATH_SEP) {
                destfname[strlen(destfname)-1] = '\x0';
            }
            break;
        case 'o':
            dest_is_dir = 1;
            break;
        case 'E':
            p = strtok(optarg, ",");
            while (p != NULL) {
                strncpy(basedir[basedircount], p,
                        sizeof(basedir[basedircount])-1);
                basedir[basedircount][sizeof(basedir[basedircount])-1] = '\x0';
                basedircount++;
                p = strtok(NULL, ",");
            }
            break;
        case 'i':
            if (filecount != 0) {
                fprintf(stderr,"Can't specify both -i and -F\n");
                exit(1);
            }
            if (strcmp(optarg, "-") == 0) {
                listfile = stdin;
            } else if ((listfile = fopen(optarg, "rt")) == NULL) {
                fprintf(stderr,"Couldn't open file list %s: %s\n",
                        optarg, strerror(errno));
                exit(1);
            }
            while (fgets(filename, sizeof(filename), listfile)) {
                if (filecount == MAXFILES) {
                    fprintf(stderr, "Exceeded maximum file count\n");
                    exit(1);
                }
                while ((strlen(filename) > 0) &&
                       ((filename[strlen(filename)-1] == '\r') ||
                        (filename[strlen(filename)-1] == '\n'))) {
                    filename[strlen(filename)-1] = '\x0';
                }
                if (strlen(filename) == 0) continue;
                strncpy(filelist[filecount], filename, sizeof(filelist[0])-1);
                filelist[filecount][sizeof(filelist[0])-1] = '\x0';
                filecount++;
            }
            if (!feof(listfile) && ferror(listfile)) {
                perror("Failed to read from file list");
                exit(1);
            }
            fclose(listfile);
            break;
        case '?':
            fprintf(stderr, USAGE);
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;
    if ((argc == 0) && (filecount == 0)) {
        fprintf(stderr, USAGE);
        exit(1);
    }
    if (unicast && (destcount != 1)) {
        fprintf(stderr, "Must specify exactly one host for unicast\n");
        exit(1);
    }

    if (announce_int > register_int) {
        fprintf(stderr, "Error: Register interval %d is less than "
                        "announce interval %d\n", register_int, announce_int);
        exit(1);
    }
    if (status_int > done_int) {
        fprintf(stderr, "Error: Done interval %d is less than "
                        "status interval %d\n", done_int, status_int);
        exit(1);
    }
    if (save_fail && sync_mode) {
        fprintf(stderr, "Error: Cannot use restart mode "
                        "and sync mode together\n");
        exit(1);
    }

    if (filecount != 0) {
        if (argc > 0) {
            fprintf(stderr, "Warning: ignoring paths "
                            "specified on command line\n");
        }
        return;
    }
    // Read list of files.  Make sure each exists.
    for (i = 0; i < argc; i++) {
        if (filecount == MAXFILES) {
            fprintf(stderr, "Exceeded maximum file count\n");
            exit(1);
        }
        strncpy(filelist[filecount], argv[i], sizeof(filelist[0])-1);
        filelist[filecount][sizeof(filelist[0])-1] = '\x0';
        filecount++;
    }
    if (keytype == KEY_NONE) {
        hashtype = HASH_NONE;
        sigtype = SIG_NONE;
    }
    if (!max_rate) {
        max_rate = rate;
    }
}

