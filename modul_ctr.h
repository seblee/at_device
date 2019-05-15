/**
****************************************************************************
 * @Warning :Without permission from the author,Not for commercial use
 * @File    :modul_ctr.h
 * @Author  :Seblee
 * @date    :2018-12-30 10:34:48
 * @version :V1.0.0
 *************************************************
 * @brief   :
 ****************************************************************************
 * @Last Modified by:   Seblee
 * @Last Modified time: 2018-12-30 10:34:48
 ****************************************************************************
**/
/* Private include -----------------------------------------------------------*/
#include <rtthread.h>
#include "sys_conf.h"
/* Private typedef -----------------------------------------------------------*/
typedef enum _module_state
{
    MODULE_IDEL,
    MODULE_INIT,
    MODULE_4G_READY,
    MODULE_WIFI_READY,
    MODULE_REINIT,
} _module_state_t;

/* Private define ------------------------------------------------------------*/

/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
extern rt_sem_t module_setup_sem;
/* Private function prototypes -----------------------------------------------*/

/* Private functions ---------------------------------------------------------*/
int esp8266_module_device_init(rt_event_t event, rt_mutex_t lock, Net_Conf_st *netcon);

int sim7600_module_device_init(rt_event_t event, rt_mutex_t lock);

int sim7600_cclk_cmd(void);

_module_state_t module_state(_module_state_t *state);

int module_thread_start(void *parameter);
void module_test_mode(void);
/*----------------------------------------------------------------------------*/
