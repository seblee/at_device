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

#include <rtthread.h>
#include <sys/socket.h>

#include <at_socket.h>
#include "network.h"
/* Private typedef -----------------------------------------------------------*/

/* Private define ------------------------------------------------------------*/

/* Private macro -------------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/
static rt_event_t at_socket_event;
static rt_mutex_t at_event_lock;

extern sys_reg_st g_sys;

rt_sem_t module_setup_sem = RT_NULL;
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
    module_setup_sem = rt_sem_create("sem", 0, RT_IPC_FLAG_FIFO);
    if (module_setup_sem == RT_NULL)
    {
        LOG_E("RT AT client port initialize failed! module_setup_sem create failed!");
        return -RT_ENOMEM;
    }

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
        rt_sem_delete(module_setup_sem);
        return -RT_ENOMEM;
    }

    /* initialize AT client */
    at_client_init(AT_DEVICE_NAME, AT_DEVICE_RECV_BUFF_LEN);

    rt_sem_release(module_setup_sem);
    do
    {
        rt_err_t result;
        result = rt_sem_take(module_setup_sem, RT_WAITING_FOREVER);
        if (result == -RT_ETIMEOUT)
        {
        }
        else
        {
            if (g_sys.config.ComPara.Net_Conf.u16Net_Sel)
            {
                SIM7600_DIR_4G;
                sim7600_module_device_init(at_socket_event, at_event_lock);
            }
            else
            {
                SIM7600_DIR_WIFI;
                sim7600_module_device_init(at_socket_event, at_event_lock);
            }
        }

    } while (1);

    return RT_EOK;
}
