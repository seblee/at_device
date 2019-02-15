/*
 * File      : at_socket_sim7600.c
 * This file is part of RT-Thread RTOS
 * COPYRIGHT (C) 2006 - 2018, RT-Thread Development Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018-06-20     chenyong     first version
 */

#include <at.h>
#include <stdio.h>
#include <string.h>

#include <rtthread.h>
#include <sys/socket.h>
#include "modul_ctr.h"
#include <at_socket.h>

#if !defined(AT_SW_VERSION_NUM) || AT_SW_VERSION_NUM < 0x10200
#error "This AT Client version is older, please check and update latest AT Client!"
#endif

#define LOG_TAG "at.sim7600"
#include <at_log.h>
#ifndef LOG_D
#error "Please update the 'rtdbg.h' file to GitHub latest version (https://github.com/RT-Thread/rt-thread/blob/master/include/rtdbg.h)"
#endif

#ifdef AT_DEVICE_SIM7600

#define SIM7600_MODULE_SEND_MAX_SIZE 2048
#define SIM7600_WAIT_CONNECT_TIME 5000
#define SIM7600_THREAD_STACK_SIZE 1024
#define SIM7600_THREAD_PRIORITY (RT_THREAD_PRIORITY_MAX / 2)

/* set real event by current socket and current state */
#define SET_EVENT(socket, event) (((socket + 1) << 16) | (event))

/* AT socket event type */
#define SIM7600_EVENT_CONN_OK (1L << 0)
#define SIM7600_EVENT_SEND_OK (1L << 1)
#define SIM7600_EVENT_RECV_OK (1L << 2)
#define SIM7600_EVNET_CLOSE_OK (1L << 3)
#define SIM7600_EVENT_CONN_FAIL (1L << 4)
#define SIM7600_EVENT_SEND_FAIL (1L << 5)
#define SIM7600_EVENT_NETOPEN_OK (1L << 6)
#define SIM7600_EVENT_NETOPEN_FAIL (1L << 7)
#define SIM7600_EVENT_SOCEKT_ON (1L << 8)
#define SIM7600_EVENT_SOCEKT_OFF (1L << 9)
#define SIM7600_EVNET_CLOSE_FAIL (1L << 10)

#define RESOLVE_RETRY 5

static int cur_socket;
static int cur_send_bfsz;
static rt_event_t at_socket_event;
static rt_mutex_t at_event_lock;
static at_evt_cb_t at_evt_cb_set[] = {
    [AT_SOCKET_EVT_RECV] = NULL,
    [AT_SOCKET_EVT_CLOSED] = NULL,
};

static int at_socket_event_send(uint32_t event)
{
    return (int)rt_event_send(at_socket_event, event);
}

static int at_socket_event_recv(uint32_t event, uint32_t timeout, rt_uint8_t option)
{
    int result = 0;
    rt_uint32_t recved;

    result = rt_event_recv(at_socket_event, event, option | RT_EVENT_FLAG_CLEAR, timeout, &recved);
    if (result != RT_EOK)
    {
        return -RT_ETIMEOUT;
    }

    return recved;
}

static int sim7600_isSocket_connected(int socket)
{
    at_response_t resp = RT_NULL;
    int result = RT_EOK, event_result = 0;
    resp = at_create_resp(64, 0, rt_tick_from_millisecond(5000));
    if (!resp)
    {
        LOG_E("No memory for response structure!");
        return -RT_ENOMEM;
    }
    rt_mutex_take(at_event_lock, RT_WAITING_FOREVER);
    cur_socket = socket;
    /*check socket connect state*/
    if (at_exec_cmd(resp, "AT+CIPCLOSE?") < 0)
    {
        result = -RT_ERROR;
        goto __exit;
    }
    /* waiting result event from AT URC */
    if (at_socket_event_recv(SET_EVENT(socket, 0), rt_tick_from_millisecond(300 * 3), RT_EVENT_FLAG_OR) < 0)
    {
        LOG_E("socket (%d) send failed, wait connect result timeout.", socket);
        result = -RT_ETIMEOUT;
        goto __exit;
    }
    /* waiting OK or failed result */
    if ((event_result = at_socket_event_recv(SIM7600_EVENT_SOCEKT_ON | SIM7600_EVENT_SOCEKT_OFF, rt_tick_from_millisecond(1 * 1000),
                                             RT_EVENT_FLAG_OR)) < 0)
    {
        LOG_E("socket (%d) send failed, wait connect OK|FAIL timeout.", socket);
        result = -RT_ETIMEOUT;
        goto __exit;
    } /* check result */
    if (event_result & SIM7600_EVENT_SOCEKT_ON)
    {
        result = 1;
        goto __exit;
    }
    else if (event_result & SIM7600_EVENT_SOCEKT_OFF)
    {
        result = 0;
        goto __exit;
    }

__exit:
    rt_mutex_release(at_event_lock);

    if (resp)
    {
        at_delete_resp(resp);
    }

    return result;
}

/**
 * close socket by AT commands.
 *
 * @param current socket
 *
 * @return  0: close socket success
 *         -1: send AT commands error
 *         -2: wait socket event timeout
 *         -5: no memory
 */
static int sim7600_socket_close(int socket)
{
    at_response_t resp = RT_NULL;
    int result = RT_EOK, event_result = 0;

    resp = at_create_resp(64, 0, rt_tick_from_millisecond(5000));
    if (!resp)
    {
        LOG_E("No memory for response structure!");
        return -RT_ENOMEM;
    }

    rt_mutex_take(at_event_lock, RT_WAITING_FOREVER);

    /*check socket connect state*/
    result = sim7600_isSocket_connected(socket);
    if (result < 0)
        goto __exit;
    else if (result == 0)
    {
        if (at_evt_cb_set[AT_SOCKET_EVT_CLOSED])
        {
            at_evt_cb_set[AT_SOCKET_EVT_CLOSED](socket, AT_SOCKET_EVT_CLOSED, RT_NULL, 0);
        }
    }
    else
    {
        if (at_exec_cmd(resp, "AT+CIPCLOSE=%d", socket) < 0)
        {
            result = -RT_ERROR;
            goto __exit;
        }
        /* waiting result event from AT URC */
        if (at_socket_event_recv(SET_EVENT(socket, 0), rt_tick_from_millisecond(300 * 3), RT_EVENT_FLAG_OR) < 0)
        {
            LOG_E("socket (%d) send failed, wait connect result timeout.", socket);
            result = -RT_ETIMEOUT;
            goto __exit;
        }
        /* waiting OK or failed result */
        if ((event_result = at_socket_event_recv(SIM7600_EVNET_CLOSE_OK | SIM7600_EVNET_CLOSE_FAIL, rt_tick_from_millisecond(1 * 1000),
                                                 RT_EVENT_FLAG_OR)) < 0)
        {
            LOG_E("socket (%d) send failed, wait connect OK|FAIL timeout.", socket);
            result = -RT_ETIMEOUT;
            goto __exit;
        } /* check result */
        if (event_result & SIM7600_EVNET_CLOSE_OK)
            result = RT_EOK;
        else if (event_result & SIM7600_EVNET_CLOSE_FAIL)
            result = -RT_ERROR;
    }

__exit:
    /* notice the socket is disconnect by remote */

    rt_mutex_release(at_event_lock);

    if (resp)
    {
        at_delete_resp(resp);
    }
    result = 0;
    return result;
}

/**
 * create TCP/UDP client or server connect by AT commands.
 *
 * @param socket current socket
 * @param ip server or client IP address
 * @param port server or client port
 * @param type connect socket type(tcp, udp)
 * @param is_client connection is client
 *
 * @return   0: connect success
 *          -1: connect failed, send commands error or type error
 *          -2: wait socket event timeout
 *          -5: no memory
 */
static int sim7600_socket_connect(int socket, char *ip, int32_t port, enum at_socket_type type, rt_bool_t is_client)
{
    at_response_t resp = RT_NULL;
    int result = RT_EOK, event_result = 0;
    rt_bool_t retryed = RT_FALSE;

    RT_ASSERT(ip);
    RT_ASSERT(port >= 0);

    resp = at_create_resp(128, 0, rt_tick_from_millisecond(5000));
    if (!resp)
    {
        LOG_E("No memory for response structure!");
        return -RT_ENOMEM;
    }
    rt_mutex_take(at_event_lock, RT_WAITING_FOREVER);
    cur_socket = socket;
    /*check socket connect state*/
    result = sim7600_isSocket_connected(socket);

    if (result < 0)
        goto __exit;
    else if (result == 1)
    {
        result = sim7600_socket_close(socket);
        if (result < 0)
            goto __exit;
    }

__retry:
    if (is_client)
    {
        switch (type)
        {
        case AT_SOCKET_TCP:
            /* send AT commands to connect TCP server */
            if (at_exec_cmd(resp, "AT+CIPOPEN=%d,\"TCP\",\"%s\",%d", socket, ip, port) < 0)
            {
                result = -RT_ERROR;
            }
            break;

        case AT_SOCKET_UDP:
            if (at_exec_cmd(resp, "AT+CIPOPEN=%d,\"UDP\",,,%d", socket, ip, port) < 0)
            {
                result = -RT_ERROR;
            }
            break;

        default:
            LOG_E("Not supported connect type : %d.", type);
            result = -RT_ERROR;
            goto __exit;
        }
    }
    /* waiting result event from AT URC */
    if (at_socket_event_recv(SET_EVENT(socket, 0), rt_tick_from_millisecond(300 * 3), RT_EVENT_FLAG_OR) < 0)
    {
        LOG_E("socket (%d) send failed, wait connect result timeout.", socket);
        result = -RT_ETIMEOUT;
        goto __exit;
    }
    /* waiting OK or failed result */
    if ((event_result = at_socket_event_recv(SIM7600_EVENT_CONN_OK | SIM7600_EVENT_CONN_FAIL, rt_tick_from_millisecond(1 * 1000),
                                             RT_EVENT_FLAG_OR)) < 0)
    {
        LOG_E("socket (%d) send failed, wait connect OK|FAIL timeout.", socket);
        result = -RT_ETIMEOUT;
        goto __exit;
    } /* check result */
    if (event_result & SIM7600_EVENT_CONN_FAIL)
    {
        if (!retryed)
        {
            LOG_E("socket (%d) connect failed, maybe the socket was not be closed at the last time and now will retry.", socket);
            if (sim7600_socket_close(socket) < 0)
            {
                goto __exit;
            }
            retryed = RT_TRUE;
            goto __retry;
        }
        LOG_E("socket (%d) connect failed, failed to establish a connection.", socket);
        result = -RT_ERROR;
        goto __exit;
    }

__exit:
    rt_mutex_release(at_event_lock);

    if (resp)
    {
        at_delete_resp(resp);
    }

    return result;
}

/**
 * send data to server or client by AT commands.
 *
 * @param socket current socket
 * @param buff send buffer
 * @param bfsz send buffer size
 * @param type connect socket type(tcp, udp)
 *
 * @return >=0: the size of send success
 *          -1: send AT commands error or send data error
 *          -2: waited socket event timeout
 *          -5: no memory
 */
static int sim7600_socket_send(int socket, const char *buff, size_t bfsz, enum at_socket_type type)
{
    int result = RT_EOK;
    int event_result = 0;
    at_response_t resp = RT_NULL;
    size_t cur_pkt_size = 0, sent_size = 0;

    RT_ASSERT(buff);
    RT_ASSERT(bfsz > 0);

    resp = at_create_resp(128, 2, rt_tick_from_millisecond(5000));
    if (!resp)
    {
        LOG_E("No memory for response structure!");
        return -RT_ENOMEM;
    }

    rt_mutex_take(at_event_lock, RT_WAITING_FOREVER);

    /* set current socket for send URC event */
    cur_socket = socket;
    /* set AT client end sign to deal with '>' sign.*/
    at_set_end_sign('>');

    while (sent_size < bfsz)
    {
        if (bfsz - sent_size < SIM7600_MODULE_SEND_MAX_SIZE)
        {
            cur_pkt_size = bfsz - sent_size;
        }
        else
        {
            cur_pkt_size = SIM7600_MODULE_SEND_MAX_SIZE;
        }

        /* send the "AT+CIPSEND" commands to AT server than receive the '>' response on the first line. */
        if (at_exec_cmd(resp, "AT+CIPSEND=%d,%d", socket, cur_pkt_size) < 0)
        {
            result = -RT_ERROR;
            goto __exit;
        }

        /* send the real data to server or client */
        result = (int)at_client_send(buff + sent_size, cur_pkt_size);
        if (result == 0)
        {
            result = -RT_ERROR;
            goto __exit;
        }

        /* waiting result event from AT URC */
        if (at_socket_event_recv(SET_EVENT(socket, 0), rt_tick_from_millisecond(5 * 1000), RT_EVENT_FLAG_OR) < 0)
        {
            LOG_E("socket (%d) send failed, wait connect result timeout.", socket);
            result = -RT_ETIMEOUT;
            goto __exit;
        }
        /* waiting OK or failed result */
        if ((event_result = at_socket_event_recv(SIM7600_EVENT_SEND_OK | SIM7600_EVENT_SEND_FAIL, rt_tick_from_millisecond(5 * 1000),
                                                 RT_EVENT_FLAG_OR)) < 0)
        {
            LOG_E("socket (%d) send failed, wait connect OK|FAIL timeout.", socket);
            result = -RT_ETIMEOUT;
            goto __exit;
        }
        /* check result */
        if (event_result & SIM7600_EVENT_SEND_FAIL)
        {
            LOG_E("socket (%d) send failed, return failed.", socket);
            result = -RT_ERROR;
            goto __exit;
        }

        if (type == AT_SOCKET_TCP)
        {
            cur_pkt_size = cur_send_bfsz;
        }

        sent_size += cur_pkt_size;
    }

__exit:
    /* reset the end sign for data */
    at_set_end_sign(0);

    rt_mutex_release(at_event_lock);

    if (resp)
    {
        at_delete_resp(resp);
    }

    return result;
}

/**
 * domain resolve by AT commands.
 *
 * @param name domain name
 * @param ip parsed IP address, it's length must be 16
 *
 * @return  0: domain resolve success
 *         -2: wait socket event timeout
 *         -5: no memory
 */
static int sim7600_domain_resolve(const char *name, char ip[16])
{

    int i, result = RT_EOK;
    char recv_ip[16] = {0};
    at_response_t resp = RT_NULL;
    RT_ASSERT(name);
    RT_ASSERT(ip);

    resp = at_create_resp(512, 0, rt_tick_from_millisecond(5000));
    if (!resp)
    {
        LOG_E("No memory for response structure!");
        return -RT_ENOMEM;
    }

    rt_mutex_take(at_event_lock, RT_WAITING_FOREVER);

    for (i = 0; i < RESOLVE_RETRY; i++)
    {
        if (at_exec_cmd(resp, "AT+CDNSGIP=\"%s\"", name) < 0)
        {
            result = -RT_ERROR;
            goto __exit;
        }

        /* parse the third line of response data, get the IP address */
        char *p = rt_strstr(resp->buf, "+CDNSGIP: ");
        for (i = 0; i < resp->line_counts - 1; i++)
        {
            p = rt_strstr(at_resp_get_line(resp, i + 1), "+CDNSGIP: ");
            if (p)
                break;
        }
        if (!p)
        {
            rt_thread_delay(rt_tick_from_millisecond(100));
            /* resolve failed, maybe receive an URC CRLF */
            continue;
        }
        if ((sscanf(p, "%*[^,],\"%*[^,],\"%s\"", recv_ip)) < 0)
        {
            rt_thread_delay(rt_tick_from_millisecond(100));
            /* resolve failed, maybe receive an URC CRLF */
            continue;
        }

        // LOG_I("recv_ip:%s,resule:%s", recv_ip, p);
        if (*(p + 10) == '0')
        {
            rt_thread_delay(rt_tick_from_millisecond(100));
            /* resolve failed, maybe receive an URC CRLF */
            continue;
        }

        if (strlen(recv_ip) < 8)
        {
            rt_thread_delay(rt_tick_from_millisecond(100));
            /* resolve failed, maybe receive an URC CRLF */
            continue;
        }
        else
        {
            strncpy(ip, recv_ip, 15);
            ip[15] = '\0';
            break;
        }
    }

__exit:
    rt_mutex_release(at_event_lock);

    if (resp)
    {
        at_delete_resp(resp);
    }

    return result;
}

/**
 * cclk by AT commands.
 *
 * @param name domain name
 * @param get module rtc
 */
int sim7600_cclk_cmd(void)
{

    int result = RT_EOK;
    at_response_t resp = RT_NULL;

    resp = at_create_resp(512, 0, rt_tick_from_millisecond(5000));
    if (!resp)
    {
        LOG_E("No memory for response structure!");
        return -RT_ENOMEM;
    }

    rt_mutex_take(at_event_lock, RT_WAITING_FOREVER);

    if (at_exec_cmd(resp, "AT+CCLK?") < 0)
    {
        result = -RT_ERROR;
        goto __exit;
    }

__exit:
    rt_mutex_release(at_event_lock);

    if (resp)
    {
        at_delete_resp(resp);
    }

    return result;
}
/**
 * set AT socket event notice callback
 *
 * @param event notice event
 * @param cb notice callback
 */
static void sim7600_socket_set_event_cb(at_socket_evt_t event, at_evt_cb_t cb)
{
    if (event < sizeof(at_evt_cb_set) / sizeof(at_evt_cb_set[1]))
    {
        at_evt_cb_set[event] = cb;
    }
}

static void urc_send_func(const char *data, rt_size_t size)
{
    int socket, reqSendLength = 0, cnfSendLength = 0;
    RT_ASSERT(data && size);
    // LOG_I("urc_send:%d", size);
    sscanf(data, "+CIPSEND: %d,%d,%d", &socket, &reqSendLength, &cnfSendLength);
    cur_send_bfsz = cnfSendLength;
    if (reqSendLength == cnfSendLength)
    {
        at_socket_event_send(SET_EVENT(cur_socket, SIM7600_EVENT_SEND_OK));
    }
    else
    {
        at_socket_event_send(SET_EVENT(cur_socket, SIM7600_EVENT_SEND_FAIL));
    }
}
static void urc_cipopen_func(const char *data, rt_size_t size)
{
    int socket, err;

    RT_ASSERT(data && size);
    // LOG_I("urc_cipopen:%d", size);
    sscanf(data, "+CIPOPEN: %d,%d", &socket, &err);
    if (err == 0)
        at_socket_event_send(SET_EVENT(socket, SIM7600_EVENT_CONN_OK));
    else
        at_socket_event_send(SET_EVENT(socket, SIM7600_EVENT_CONN_FAIL));
}

static void urc_cipclose_func(const char *data, rt_size_t size)
{
    int socket[10], err;
    RT_ASSERT(data && size);
    LOG_I("urc_cipclose:%d", size);
    if (size < 20)
    {
        sscanf(data, "+CIPCLOSE: %d,%d", &socket[0], &err);
        // rt_kprintf("Socket:%d Close %s\n", socket, (err == 0) ? "Sucess" : "Failed");
        LOG_W("+CIPCLOSE: %d,%d", socket[0], err);
        at_socket_event_send(SET_EVENT(socket[0], (err == 0) ? SIM7600_EVNET_CLOSE_OK : SIM7600_EVNET_CLOSE_FAIL));

        /* notice the socket is disconnect by remote */
        if (at_evt_cb_set[AT_SOCKET_EVT_CLOSED])
        {
            at_evt_cb_set[AT_SOCKET_EVT_CLOSED](socket[0], AT_SOCKET_EVT_CLOSED, RT_NULL, 0);
        }
    }
    else
    {
        sscanf(data, "+CIPCLOSE: %d,%d,%d,%d,%d,%d,%d,%d,%d,%d", &socket[0], &socket[1], &socket[2], &socket[3], &socket[4], &socket[5], &socket[6], &socket[7], &socket[8], &socket[9]);
        if (socket[cur_socket] == 1)
            at_socket_event_send(SET_EVENT(cur_socket, SIM7600_EVENT_SOCEKT_ON));
        else if (socket[cur_socket] == 0)
            at_socket_event_send(SET_EVENT(cur_socket, SIM7600_EVENT_SOCEKT_OFF));
    }
}

static void urc_ipclose_func(const char *data, rt_size_t size)
{
    int socket, reason;

    RT_ASSERT(data && size);
    // LOG_I("urc_ipclose:%d", size);
    sscanf(data, "+IPCLOSE: %d,%d", &socket, &reason);
    LOG_W("+IPCLOSE: %d,%d", socket, reason);
    /* notice the socket is disconnect by remote */
    if (at_evt_cb_set[AT_SOCKET_EVT_CLOSED])
    {
        at_evt_cb_set[AT_SOCKET_EVT_CLOSED](socket, AT_SOCKET_EVT_CLOSED, RT_NULL, 0);
    }
}

static void urc_recv_func(const char *data, rt_size_t size)
{
    int socket = 0;
    rt_size_t bfsz = 0, temp_size = 0;
    rt_int32_t timeout;
    char *recv_buf = RT_NULL, temp[8];

    RT_ASSERT(data && size);
    // LOG_I("urc_recv:%d", size);
    /* get the current socket and receive buffer size by receive data */
    sscanf(data, "+RECEIVE,%d,%d", &socket, (int *)&bfsz);
    /* get receive timeout by receive buffer length */
    timeout = bfsz;

    if (socket < 0 || bfsz == 0)
        return;

    recv_buf = rt_calloc(1, bfsz);
    if (!recv_buf)
    {
        LOG_E("no memory for URC receive buffer (%d)!", bfsz);
        /* read and clean the coming data */
        while (temp_size < bfsz)
        {
            if (bfsz - temp_size > sizeof(temp))
            {
                at_client_recv(temp, sizeof(temp), timeout);
            }
            else
            {
                at_client_recv(temp, bfsz - temp_size, timeout);
            }
            temp_size += sizeof(temp);
        }
        return;
    }

    /* sync receive data */
    if (at_client_recv(recv_buf, bfsz, timeout) != bfsz)
    {
        LOG_E("receive size(%d) data failed!", bfsz);
        rt_free(recv_buf);
        return;
    }

    /* notice the receive buffer and buffer size */
    if (at_evt_cb_set[AT_SOCKET_EVT_RECV])
    {
        at_evt_cb_set[AT_SOCKET_EVT_RECV](socket, AT_SOCKET_EVT_RECV, recv_buf, bfsz);
    }
}

static void urc_net_func(const char *data, rt_size_t size)
{
    int result;
    RT_ASSERT(data && size);
    // LOG_I("urc_netopen:%d", size);
    sscanf(data, "+NETOPEN: %d", &result);
    if (result == 0)
        at_socket_event_send(SIM7600_EVENT_NETOPEN_OK);
    else
    {
        at_socket_event_send(SIM7600_EVENT_NETOPEN_FAIL);
        LOG_I("opens packet network failed:%d", result);
    }
}

static void urc_ping_func(const char *data, rt_size_t size)
{
    int result_type, data_packet_size, rtt, TTL;
    int num_pkts_sent, num_pkts_recvd, num_pkts_lost, min_rtt, max_rtt, avg_rtt;
    char resolved_ip_addr[16];
    RT_ASSERT(data && size);
    // LOG_I("urc_ping:%d", size);
    sscanf(data, "+CPING: %d,%*s", &result_type);

    switch (result_type)
    {
    case 1:
        sscanf(data, "+CPING: %d,%[^,],%d,%d,%d", &result_type, resolved_ip_addr, &data_packet_size, &rtt, &TTL);
        rt_kprintf("from %s bytes=%d time=%d TTL=%d\n", resolved_ip_addr, data_packet_size, rtt, TTL);
        break;
    case 2:
        rt_kprintf("Ping time out\n");
        break;
    case 3:
        sscanf(data, "+CPING: %d,%d,%d,%d,%d,%d,%d", &result_type, &num_pkts_sent, &num_pkts_recvd, &num_pkts_lost, &min_rtt, &max_rtt, &avg_rtt);
        rt_kprintf("Ping result:num_sent:%d,num_recvd:%d,num_lost:%d,min_rtt:%d,max_rtt:%d,avg_rtt:%d\n", num_pkts_sent, num_pkts_recvd, num_pkts_lost, min_rtt, max_rtt, avg_rtt);
        break;
    default:
        break;
    }
}
static void urc_cgmr_func(const char *data, rt_size_t size)
{
    RT_ASSERT(data && size);
    // LOG_I("urc_cgmr:%d", size);
    rt_kprintf("Firmware:%s\n", data + strlen("+CGMR: "));
}
static void urc_cntp_func(const char *data, rt_size_t size)
{
    int err;
    RT_ASSERT(data && size);
    // LOG_I("urc_cntp:%d", size);
    sscanf(data, "+CNTP: %d", &err);
    if (err == 0)
        LOG_I("CNTP START");
    else
        LOG_E("CNTP error:%d", err);
}
static void urc_cclk_func(const char *data, rt_size_t size)
{
    int yy, mm, dd, hh, MM, ss, zone;
    time_t now;
    struct tm ti;
    rt_device_t device;
    RT_ASSERT(data && size);
    // LOG_I("urc_cclk:%d", size);
    sscanf(data, "+CCLK: \"%d/%d/%d,%d:%d:%d+%d\"", &yy, &mm, &dd, &hh, &MM, &ss, &zone);
    rt_kprintf("<time>:20%d-%d-%d %d:%d:%d %d\n", yy, mm, dd, hh, MM, ss, zone);
    ti.tm_year = yy + 2000 - 1900;
    ti.tm_mon = mm - 1;
    ti.tm_mday = dd;
    ti.tm_hour = hh;
    ti.tm_min = MM;
    ti.tm_sec = ss;
    now = mktime(&ti);
    now -= zone * 900;
    device = rt_device_find("rtc");
    if (device != RT_NULL)
    {
        rt_device_control(device, RT_DEVICE_CTRL_RTC_SET_TIME, &now);
    }
}
static void urc_cipevent_func(const char *data, rt_size_t size)
{
    RT_ASSERT(data && size);
    LOG_I("urc_cipevent:%d", size);
    if (strstr(data, "NETWORK CLOSED UNEXPECTEDLY"))
    {
        if (at_evt_cb_set[AT_SOCKET_EVT_CLOSED])
        {
            at_evt_cb_set[AT_SOCKET_EVT_CLOSED](0, AT_SOCKET_EVT_CLOSED, RT_NULL, 0);
            at_evt_cb_set[AT_SOCKET_EVT_CLOSED](1, AT_SOCKET_EVT_CLOSED, RT_NULL, 0);
            at_evt_cb_set[AT_SOCKET_EVT_CLOSED](2, AT_SOCKET_EVT_CLOSED, RT_NULL, 0);
            at_evt_cb_set[AT_SOCKET_EVT_CLOSED](3, AT_SOCKET_EVT_CLOSED, RT_NULL, 0);
        }
        if (module_state(RT_NULL) >= MODULE_4G_READY)
        {
            _module_state_t state = MODULE_REINIT;
            module_state(&state);
        }
    }
}
static void urc_iperror_func(const char *data, rt_size_t size)
{
    RT_ASSERT(data && size);
    // LOG_I("urc_iperror:%d", size);
    LOG_E("ip error:%s\n", data + strlen("+IP ERROR: "));
}
static void urc_pbdone_func(const char *data, rt_size_t size)
{
    RT_ASSERT(data && size);
    // LOG_I("urc_pbdone:%d", size);
    if (strstr(data, "PB DONE"))
    {
        if (module_state(RT_NULL) >= MODULE_4G_READY)
        {
            _module_state_t state = MODULE_REINIT;
            module_state(&state);
        }
    }
}

static struct at_urc urc_table[] = {
    {"+NETOPEN", "\r\n", urc_net_func},
    {"+CIPOPEN:", "\r\n", urc_cipopen_func},
    {"+CIPSEND:", "\r\n", urc_send_func},
    {"+RECEIVE", "\r\n", urc_recv_func},
    {"+CIPCLOSE:", "\r\n", urc_cipclose_func},
    {"+IPCLOSE:", "\r\n", urc_ipclose_func},
    {"+CPING", "\r\n", urc_ping_func},
    {"+CGMR", "\r\n", urc_cgmr_func},
    {"+CNTP:", "\r\n", urc_cntp_func},
    {"+CCLK:", "\r\n", urc_cclk_func},
    {"+CIPEVENT:", "\r\n", urc_cipevent_func},
    {"+IP ERROR: ", "\r\n", urc_iperror_func},
    {"PB DONE", "\r\n", urc_pbdone_func},
};

#define AT_SEND_CMD(resp, cmd)                                                                    \
    do                                                                                            \
    {                                                                                             \
        if (at_exec_cmd(at_resp_set_info(resp, 256, 0, rt_tick_from_millisecond(5000)), cmd) < 0) \
        {                                                                                         \
            LOG_E("RT AT send commands(%s) error!", cmd);                                         \
            result = -RT_ERROR;                                                                   \
            goto __exit;                                                                          \
        }                                                                                         \
    } while (0);

static void sim7600_init_thread_entry(void *parameter)
{
    at_response_t resp = RT_NULL;
    rt_err_t result = RT_EOK;
    rt_size_t i;
    static int retry = 0;
    _module_state_t state = MODULE_INIT;
    static rt_uint8_t thread_active = 0;

    if (thread_active)
        return;
    else
        thread_active = 1;
    module_state(&state);

    resp = at_create_resp(128, 0, rt_tick_from_millisecond(5000));
    if (!resp)
    {
        LOG_E("No memory for response structure!");
        result = -RT_ENOMEM;
        goto __exit;
    }

    LOG_I("start init");
    i = 0;
    do
    {
        if (i > RESOLVE_RETRY)
        {
            result = -RT_ENOMEM;
            goto __exit;
        }
        rt_thread_delay(rt_tick_from_millisecond(2000));
    } while ((at_exec_cmd(resp, "AT") < 0) && (i++ < 200));
    /* reset module */
    // AT_SEND_CMD(resp, "AT+CFUN=1,1");
    // AT_SEND_CMD(resp, "AT+CRESET");
    AT_SEND_CMD(resp, "AT+CFUN=0");
    rt_thread_delay(rt_tick_from_millisecond(2000));
    AT_SEND_CMD(resp, "AT+CFUN=1");
    /* reset waiting delay */
    rt_thread_delay(rt_tick_from_millisecond(5000));

    i = 0;
    do
    {
        if (i > RESOLVE_RETRY)
        {
            result = -RT_ENOMEM;
            goto __exit;
        }
        rt_thread_delay(rt_tick_from_millisecond(2000));
    } while ((at_exec_cmd(resp, "AT") < 0) && (i++ < 200));
    rt_thread_delay(rt_tick_from_millisecond(1000));
    /* disable echo */
    AT_SEND_CMD(resp, "ATE0");
    /* Request model identification */
    AT_SEND_CMD(resp, "AT+CGMM");
    /* Request revision identification */
    AT_SEND_CMD(resp, "AT+CGMR");
    i = 10;
    do
    {
        //+CPIN: READY
        if (at_exec_cmd(at_resp_set_info(resp, 256, 4, rt_tick_from_millisecond(5000)), "AT+CPIN?") == RT_EOK)
        {
            /* parse the third line of response data, get the IP address */
            if (!strstr(at_resp_get_line(resp, 2), "+CPIN: READY"))
            {
                LOG_E("checkout sim card failed");
                result = -RT_ENOMEM;
                goto __exit;
            }
            else
                break;
        }
        rt_thread_delay(rt_tick_from_millisecond(1000));
    } while (i--);

    i = 0;
    do
    {
        int ncode, stat;
        if (at_exec_cmd(resp, "AT+CREG?") == RT_EOK)
        {
            /* parse the third line of response data, get the IP address */
            if (at_resp_parse_line_args_by_kw(resp, "+CREG:", "+CREG: %d,%d", &ncode, &stat) > 0)
            {
                rt_thread_delay(rt_tick_from_millisecond(1000));
                LOG_E("ncode:%d, stat:%d", ncode, stat);
                if (stat == 1)
                    break;
            }
        }
    } while (i++ < 100);
    /* set ntc server */
    AT_SEND_CMD(resp, "AT+CNTP=\"ntp.aliyun.com\",32");
    /* operation ntc */
    AT_SEND_CMD(resp, "AT+CNTP");
    rt_thread_delay(rt_tick_from_millisecond(2000));
    /* Select sending mode */
    AT_SEND_CMD(resp, "AT+CIPSENDMODE=0");
    /* Add an IP head when receiving data */
    AT_SEND_CMD(resp, "AT+CIPHEAD=1");
    /* Show Remote IP address and Port */
    AT_SEND_CMD(resp, "AT+CIPSRIP=0");
    /* Select TCP/IP application mode */
    AT_SEND_CMD(resp, "AT+CIPMODE=0");
    /* Select TCP/IP application mode */
    AT_SEND_CMD(resp, "AT+CIPCCFG=10,0,0,1,1,0,500");
    // AT_SEND_CMD(resp, "AT+CIPCCFG?");
    rt_thread_delay(rt_tick_from_millisecond(1000));
    AT_SEND_CMD(resp, "AT+NETOPEN");
    /* Open socket */
    int event_result;
    if ((event_result = at_socket_event_recv(SIM7600_EVENT_NETOPEN_OK | SIM7600_EVENT_NETOPEN_FAIL, rt_tick_from_millisecond(5 * 1000),
                                             RT_EVENT_FLAG_OR)) < 0)
    {
        LOG_E("AT+NETOPEN timeout.");
        result = -RT_ETIMEOUT;
        goto __exit;
    }
    /* check result */
    if (event_result & SIM7600_EVENT_NETOPEN_OK)
    {
        LOG_I("netopen sucess.....");
        result = RT_EOK;
    }
    else if (event_result & SIM7600_EVENT_NETOPEN_FAIL)
    {
        result = -RT_ERROR;
        goto __exit;
    }

    rt_thread_delay(rt_tick_from_millisecond(2000));
    /* Inquire socket PDP address */
    AT_SEND_CMD(resp, "AT+IPADDR");
    /* show module version */
    rt_thread_delay(rt_tick_from_millisecond(2000));
    /* Inquire socket PDP address */
    AT_SEND_CMD(resp, "AT+CCLK?");
    /* show module version */

__exit:
    if (resp)
    {
        at_delete_resp(resp);
    }

    if (!result)
    {
        LOG_I("AT network initialize success!");
        state = MODULE_4G_READY;
        module_state(&state);
        retry = 0;
    }
    else
    {
        LOG_E("AT network initialize failed (%d)!", result);
        result = 0;
        rt_thread_delay(rt_tick_from_millisecond(3000));
        if (retry++ < RESOLVE_RETRY)
            state = MODULE_REINIT;
        else
            state = MODULE_IDEL;
        module_state(&state);
    }
    thread_active = 0;
}

int sim7600_net_init(void)
{
#ifdef PKG_AT_INIT_BY_THREAD
    rt_thread_t tid;

    tid = rt_thread_create("sim7600_net_init", sim7600_init_thread_entry, RT_NULL, SIM7600_THREAD_STACK_SIZE, SIM7600_THREAD_PRIORITY, 20);
    if (tid)
    {
        rt_thread_startup(tid);
    }
    else
    {
        LOG_E("Create AT initialization thread fail!");
    }
#else
    sim7600_init_thread_entry(RT_NULL);
#endif

    return RT_EOK;
}

int sim7600_ping(int argc, char **argv)
{
    at_response_t resp = RT_NULL;

    if (argc != 2)
    {
        rt_kprintf("Please input: at_ping <host address>\n");
        return -RT_ERROR;
    }

    resp = at_create_resp(64, 0, rt_tick_from_millisecond(5000));
    if (!resp)
    {
        rt_kprintf("No memory for response structure!\n");
        return -RT_ENOMEM;
    }

    if (at_exec_cmd(resp, "AT+CPING=\"%s\",1", argv[1]) < 0)
    {
        rt_kprintf("ping: unknown remote server host\n");
        at_delete_resp(resp);
        return -RT_ERROR;
    }

    if (resp)
    {
        at_delete_resp(resp);
    }

    return RT_EOK;
}
#ifdef RT_USING_FINSH
#include <finsh.h>
// FINSH_FUNCTION_EXPORT(sim7600_ping, 7600_at_ping mqtt client);
// FINSH_FUNCTION_EXPORT(mq_publish, publish mqtt msg);
#ifdef FINSH_USING_MSH
#include <finsh.h>
MSH_CMD_EXPORT_ALIAS(sim7600_net_init, at_4g_init, initialize AT network);
MSH_CMD_EXPORT_ALIAS(sim7600_ping, at_4g_ping, AT ping network host);
#endif
#endif

static const struct at_device_ops sim7600_socket_ops = {
    sim7600_socket_connect,
    sim7600_socket_close,
    sim7600_socket_send,
    sim7600_domain_resolve,
    sim7600_socket_set_event_cb,
};

int sim7600_at_socket_device_init(void)
{
    /* create current AT socket event */
    at_socket_event = rt_event_create("at_se", RT_IPC_FLAG_FIFO);
    if (at_socket_event == RT_NULL)
    {
        LOG_E("RT AT client port initialize failed! at_sock_event create failed!");
        return -RT_ENOMEM;
    }

    /* create current AT socket event lock */
    at_event_lock = rt_mutex_create("at_se", RT_IPC_FLAG_FIFO);
    if (at_event_lock == RT_NULL)
    {
        LOG_E("RT AT client port initialize failed! at_sock_lock create failed!");
        rt_event_delete(at_socket_event);
        return -RT_ENOMEM;
    }

    /* initialize AT client */
    at_client_init(AT_DEVICE_NAME, AT_DEVICE_RECV_BUFF_LEN);

    /* register URC data execution function  */
    at_set_urc_table(urc_table, sizeof(urc_table) / sizeof(urc_table[0]));

    /* initialize sim7600 network */
    sim7600_net_init();

    /* set sim7600 AT Socket options */
    at_socket_device_register(&sim7600_socket_ops);

    return RT_EOK;
}
//INIT_APP_EXPORT(sim7600_at_socket_device_init);
int sim7600_module_device_init(rt_event_t event, rt_mutex_t lock)
{
    at_socket_event = event;
    at_event_lock = lock;
    LOG_D("at_set_urc_table");
    /* register URC data execution function  */
    at_set_urc_table(urc_table, sizeof(urc_table) / sizeof(urc_table[0]));
    LOG_D("sim7600_net_init");
    /* initialize sim7600 network */
    sim7600_net_init();

    /* set sim7600 AT Socket options */
    at_socket_device_register(&sim7600_socket_ops);

    return RT_EOK;
}

#endif /* AT_DEVICE_SIM7600 */
