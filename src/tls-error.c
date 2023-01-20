/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 2014 Truman Lackey <lacktrum@gmail.com>
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


#include "common.h"
#include "tls-error.h"
#include "heap.h"
#include "network.h"

void send_tls_alert(int fd, unsigned char tls_major_ver, 
	unsigned char tls_minor_ver, unsigned int msg_len, unsigned char level, unsigned char description, 
	char *MAC, ssize_t mac_len,  char *padding, ssize_t padding_len)
{

	char *msg_buff;
	/* notify the client of the failure */
	tls_alert_msg msg;
	init_tls_alert_msg(&msg, tls_major_ver, 
		tls_minor_ver, msg_len, level, description, 
		MAC, mac_len,  padding, padding_len);
	
	msg_buff = (char *)safecalloc(1, 7 + mac_len + padding_len);
	if(NULL == msg_buff)
	{
		destroy_tls_alert_msg(&msg);
		return;
	}	
	
	memcpy(msg_buff, &msg, 7);
	if(mac_len > 0 && NULL != MAC)
	{
		memcpy(msg_buff + 7, MAC, mac_len);
	}

	if(padding_len > 0 && NULL != padding)
	{
		memcpy(msg_buff + 7 + mac_len, padding, padding_len);
	}

	safe_write(fd, msg_buff, 7 + mac_len + padding_len);
	destroy_tls_alert_msg(&msg);
	safefree(msg_buff);	
}

int init_tls_alert_msg(tls_alert_msg *msg, unsigned char tls_major_ver, 
	unsigned char tls_minor_ver, unsigned int msg_len, unsigned char level, unsigned char description, 
	char *MAC, ssize_t mac_len,  char *padding, ssize_t padding_len)
{
	msg->signature = TLS_ALERT_SIG;
	msg->tls_major_ver = tls_major_ver;
	msg->tls_minor_ver = tls_minor_ver;
	msg->msg_len = msg_len;
	msg->level = level;
	msg->description = description;
	
	if(NULL != MAC)
	{
		msg->MAC = (char *)safecalloc(1, mac_len);

		if(NULL == msg->MAC)
		{
			return -1;
		}
		memcpy(msg->MAC,MAC,mac_len);
	}

	if(NULL != padding)
	{
		msg->padding = (char *)safecalloc(1, padding_len);
		if(NULL == msg->padding)
		{
			if(NULL != msg->MAC)
			{
				safefree(msg->MAC);
			}
			return -1;
		}
		memcpy(msg->padding,padding,padding_len);
	}

	return 0;
}

void destroy_tls_alert_msg(tls_alert_msg *msg)
{
	if(msg->MAC)
		safefree(msg->MAC);

	if(msg->padding)
		safefree(msg->padding);
}
