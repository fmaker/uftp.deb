/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2010   Dennis A. Bush, Jr.   bush@tcnj.edu
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

#ifndef _CLIENT_COMMON_H
#define _CLIENT_COMMON_H

int find_file(uint32_t group_id);
int interface_in_list(uint32_t *addrlist, int size);
int addr_in_list(int listidx, uint32_t *addrlist, int size);
void read_restart_file(int listidx);
void file_cleanup(int listidx, int abort);
void set_uftp_header(struct uftp_h *header, int func, int listidx);
void set_timeout(int listidx);
void send_abort(int listidx, const char *message);
void handle_abort(int listidx, const unsigned char *message, int meslen);
void send_key_req();
void handle_proxy_key(const struct sockaddr_in *src,
                      const unsigned char *message);
void clear_path(const char *path, int listidx);
void move_to_backup(int listidx);
int create_path_to_file(int listidx, const char *filename);

#endif  // _CLIENT_COMMON_H

