/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 2013 Truman Lackey <lacktrum@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#ifndef TINYPROXY_TLS_ERROR_H
#define TINYPROXY_TLS_ERROR_H

#define TLS_ALERT_SIG 0x15
#define TLS_ALERT_TYPE_WARN 0x01
#define TLS_ALERT_TYPE_FATAL 0x02

#define TLS_DESC_HANDSHAKE_FAILURE 0X28

typedef struct 
{
	unsigned char signature;
	unsigned char tls_major_ver;
	unsigned char tls_minor_ver;
	uint16_t msg_len;
	unsigned char level;
	unsigned char description;
	char *MAC;
	char *padding;
}tls_alert_msg;

void send_tls_alert(int fd, unsigned char tls_major_ver, 
	unsigned char tls_minor_ver, unsigned int msg_len, unsigned char level, unsigned char description, 
	char *MAC, ssize_t mac_len,  char *padding, ssize_t padding_len);
int init_tls_alert_msg(tls_alert_msg *msg, unsigned char tls_major_ver, 
	unsigned char tls_minor_ver, unsigned int msg_len, unsigned char level, unsigned char description, 
	char *MAC, ssize_t mac_len,  char *padding, ssize_t padding_len);
void destroy_tls_alert_msg(tls_alert_msg *msg);
#endif /* !TINYPROXY_TLS_ERROR_H */
