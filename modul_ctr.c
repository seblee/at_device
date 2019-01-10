/**
****************************************************************************
 * @Warning :Without permission from the author,Not for commercial use
 * @File    :modul_ctr.c
 * @Author  :Seblee
 * @date    :2018-12-28 13:44:34
 * @version :V1.0.0
 *************************************************
 * @brief   :
 ****************************************************************************
 * @Last Modified by:   Seblee
 * @Last Modified time: 2018-12-28 13:44:34
 ****************************************************************************
**/
/* Private include -----------------------------------------------------------*/
#include <at.h>
#include <stdio.h>
#include <string.h>
#include "modul_ctr.h"

#include <sys/socket.h>

#include <at_socket.h>
#include "network.h"

#define LOG_TAG "at.esp8266"
#include <at_log.h>
/* Private typedef -----------------------------------------------------------*/

/* Private define ------------------------------------------------------------*/
#define TIME_SYNC_SHIELD 3600 //second
/* Private macro -------------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/
static rt_event_t at_socket_event;
static rt_mutex_t at_event_lock;
rt_sem_t module_setup_sem = RT_NULL;

extern sys_reg_st g_sys;
/* Private function prototypes -----------------------------------------------*/

/* Private functions ---------------------------------------------------------*/

/*----------------------------------------------------------------------------*/

/**
 ****************************************************************************
 * @Function : void modul_control_thread_entry(void *parameter)
 * @File     : modul_ctr.c
 * @Program  : input para
 * @Created  : 2018-12-28 by seblee
 * @Brief    : control wifi & 4G control
 * @Version  : V1.0
**/
void modul_control_thread_entry(void *parameter)
{
    rt_err_t result;
    Net_Conf_st net_config;
    static rt_uint16_t u16Net_Sel_bak = 0, count = 0;
    module_setup_sem = rt_sem_create("sem", 0, RT_IPC_FLAG_FIFO);
    if (module_setup_sem == RT_NULL)
    {
        LOG_E("RT AT client port initialize failed! module_setup_sem create failed!");
        result = -RT_ENOMEM;
        goto _exit;
    }

    /* create current AT socket event */
    at_socket_event = rt_event_create("at_se", RT_IPC_FLAG_FIFO);
    if (at_socket_event == RT_NULL)
    {
        LOG_E("RT AT client port initialize failed! at_sock_event create failed!");
        result = -RT_ENOMEM;
        goto _exit;
    }

    /* create current AT socket event lock */
    at_event_lock = rt_mutex_create("at_se", RT_IPC_FLAG_FIFO);
    if (at_event_lock == RT_NULL)
    {
        LOG_E("RT AT client port initialize failed! at_sock_lock create failed!");
        rt_event_delete(at_socket_event);
        rt_sem_delete(module_setup_sem);
        result = -RT_ENOMEM;
        goto _exit;
    }

    /* initialize AT client */
    at_client_init(AT_DEVICE_NAME, AT_DEVICE_RECV_BUFF_LEN);
    rt_thread_delay(rt_tick_from_millisecond(2000));
    rt_sem_release(module_setup_sem);
    do
    {
        result = rt_sem_take(module_setup_sem, 1000);
        if (result == -RT_ETIMEOUT)
        {

            if (count++ > TIME_SYNC_SHIELD)
            {
                count = 0;
                if (u16Net_Sel_bak)
                    sim7600_cclk_cmd();
            }
            network_Conversion_wifi_parpmeter(&g_sys.config.ComPara.Net_Conf, &net_config);
            if (u16Net_Sel_bak != net_config.u16Net_Sel)
                rt_sem_release(module_setup_sem);
        }
        else
        {
            LOG_I("Moudule initialize start......");
            u16Net_Sel_bak = net_config.u16Net_Sel;
            // if (net_config.u16Net_Sel)
            {
                DIR_7600();
                sim7600_module_device_init(at_socket_event, at_event_lock);
            }
            // else
            // {
            //     DIR_8266();
            //     if (net_config.u16Net_WifiSet == WIFI_SET)
            //     {
            //         esp8266_module_device_init(at_socket_event, at_event_lock, &net_config);
            //     }
            // }
        }
    } while (1);
_exit:
    result = result;
}

/**
 ****************************************************************************
 * @Function : _module_state_t module_state(_module_state_t *state)
 * @File     : modul_ctr.c
 * @Program  : state:to set
 * @Created  : 2018-12-30 by seblee
 * @Brief    : set or get moudule state
 * @Version  : V1.0
**/
_module_state_t module_state(_module_state_t *state)
{
    static _module_state_t module_state = MODULE_IDEL;
    static rt_mutex_t mutex = RT_NULL;
    if (!mutex)
    {
        mutex = rt_mutex_create("mutex", RT_IPC_FLAG_FIFO);
        RT_ASSERT(mutex != RT_NULL);
    }
    if (state)
    {
        rt_mutex_take(mutex, RT_WAITING_FOREVER);
        module_state = *state;
        rt_mutex_release(mutex);
    }
    return module_state;
}

/**
 ****************************************************************************
 * @Function : int module_thread_start(void*parameter)
 * @File     : modul_ctr.c
 * @Program  : none
 * @Created  : 2019-01-03 by seblee
 * @Brief    : start a thread
 * @Version  : V1.0
**/
int module_thread_start(void *parameter)
{
    rt_err_t result;
    rt_thread_t tid;
    int stack_size = 512;
    int priority = RT_THREAD_PRIORITY_MAX / 3;
    char *stack;
    static int is_started = 0;
    if (is_started)
    {
        LOG_D("module_thread has already started!");
        return RT_EOK;
    }
    tid = rt_malloc(RT_ALIGN(sizeof(struct rt_thread), 8) + stack_size);
    if (!tid)
    {
        LOG_E("no memory for thread: MQTT");
        return -1;
    }
    stack = (char *)tid + RT_ALIGN(sizeof(struct rt_thread), 8);
    result = rt_thread_init(tid,
                            "module",
                            modul_control_thread_entry, // fun
                            parameter,                  // parameter
                            stack, stack_size,          // stack, size
                            priority, 5                 // priority, tick
    );
    if (result == RT_EOK)
    {
        rt_thread_startup(tid);
        is_started = 1;
    }
    return RT_EOK;
}