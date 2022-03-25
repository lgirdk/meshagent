/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2018 RDK Management
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef _RDKB_MESH_AGENT_C_
#define _RDKB_MESH_AGENT_C_

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdarg.h>
#include "stdbool.h"
#include <pthread.h>
#include <syscfg/syscfg.h>
#include <sysevent/sysevent.h>
#include <fcntl.h>

#include "cosa_mesh_parodus.h"
#include <libparodus/libparodus.h>
#include <cjson/cJSON.h>
#include <math.h>
#include "ansc_platform.h"
#include "meshsync_msgs.h"
//#include "ccsp_trace.h"
#include "cosa_apis_util.h"
#include "cosa_meshagent_internal.h"
#include "meshagent.h"
#include "mesh_client_table.h"
#include "ssp_global.h"
#include "cosa_webconfig_api.h"
#include "safec_lib_common.h"

// TELEMETRY 2.0 //RDKB-26019
#include <telemetry_busmessage_sender.h>

libpd_instance_t mesh_agent_instance;
static char deviceMAC[32] = {'\0'};

typedef struct _notify_params
{
    int evt_type;
    int evt_id;
    char mac[MAX_MAC_ADDR_LEN];
} notify_params_t;

typedef struct _mesh_event_notify
{
    int evt_id;
    char *event_string;
} mesh_event_notify_t;

mesh_event_notify_t mesh_event[] =
{
    {EB_RFC_DISABLED,   "EB_RFC_DISABLE"},
    {EB_XHS_PORT,       "EB_XHS_PORT"},
    {EB_GENERIC_ISSUE,  "EB_GENERIC_ISSUE"},
};

#define MAX_PARAMETERNAME_LEN       512
#define DEVICE_MAC                  "Device.X_CISCO_COM_CableModem.MACAddress"
#define DEVICE_PROPS_FILE           "/etc/device.properties"
#define CONTENT_TYPE_JSON           "application/json"
#define DEVINFO_CMD_FMT             "/usr/sbin/deviceinfo.sh -%s"
#define DEVINFO_MAX_LEN             32
#define DEVINFO_CMD_MAX             DEVINFO_MAX_LEN + 32
#define DEVINFO_CM_MAC              "cmac"


static void get_parodus_url(char **url);
void initparodusTask();
void* connect_parodus(void* arg);
void* sendNotification(void* str);
static void get_parodus_url(char **url);
const char *rdk_logger_module_fetch(void);

static void get_parodus_url(char **url)
{
    FILE *fp = fopen(DEVICE_PROPS_FILE, "r");

    if( NULL != fp ) {
        char str[255] = {'\0'};
        while( fscanf(fp,"%s", str) != EOF) {
            char *value = NULL;
            if( ( value = strstr(str, "PARODUS_URL=") ) ) {
                value = value + strlen("PARODUS_URL=");
                *url = strdup(value);
                MeshInfo("parodus url is %s\n", *url);
            }
        }
        fclose(fp);
    } else {
        MeshError("Failed to open device.properties file:%s\n", DEVICE_PROPS_FILE);
    }

    if( NULL == *url ) {
        MeshError("parodus url is not present in device.properties file\n");
    }

    MeshInfo("parodus url formed is %s\n", *url);
}

void initparodusTask()
{
    int err = 0;
    pthread_t parodusThreadId;

    err = pthread_create(&parodusThreadId, NULL, connect_parodus, NULL);
    if (err != 0)
    {
        MeshError("Error creating messages thread :[%s]\n", strerror(err));
    }
    else
    {
        MeshInfo("connect_parodus thread created Successfully\n");
    }
}

void* connect_parodus(void* arg)
{
    int backoffRetryTime = 0;
    int backoff_max_time = 5;
    int max_retry_sleep;
    int c =2;   //Retry Backoff count shall start at c=2 & calculate 2^c - 1.
    char *parodus_url = NULL;
    UNREFERENCED_PARAMETER(arg);
    pthread_detach(pthread_self());

    max_retry_sleep = (int) pow(2, backoff_max_time) -1;
    /*max_retry_sleep = 31;*/
    MeshDebug("max_retry_sleep is %d\n", max_retry_sleep );

    get_parodus_url(&parodus_url);
    MeshDebug("parodus_url is %s\n", parodus_url );

    libpd_cfg_t cfg = { .service_name = "mesh_agent",
                        .receive = false,
                        .keepalive_timeout_secs = 0,
                        .parodus_url = parodus_url,
                        .client_url = NULL
                      };

    while(1)
    {
        if(backoffRetryTime < max_retry_sleep)
        {
            backoffRetryTime = (int) pow(2, c) -1;
        }

        MeshDebug("New backoffRetryTime value calculated as %d seconds\n", backoffRetryTime);
        int ret = libparodus_init (&mesh_agent_instance, &cfg);

        if(ret ==0)
        {
            MeshInfo("Init for parodus Success..!!\n");
            break;
        }
        else
        {
            MeshError("Init for parodus (url %s) failed: '%s'\n", parodus_url, libparodus_strerror(ret));
            if( NULL == parodus_url ) {
                get_parodus_url(&parodus_url);
                cfg.parodus_url = parodus_url;
            }
            sleep(backoffRetryTime);
            c++;

            if(backoffRetryTime == max_retry_sleep)
            {
            c = 2;
            backoffRetryTime = 0;
            MeshDebug("backoffRetryTime reached max value, reseting to initial value\n");
            }
        }
            libparodus_shutdown(&mesh_agent_instance);

    }
    return NULL;
}

void notifyEvent(int evt_type, int evt_id, const char * pod_mac)
{
    int err = 0;
    notify_params_t *param;
    pthread_t NotificationThreadId;

    if(pod_mac == NULL) {
        MeshError("Calling notifyEvent with NULL pod_mac\n");
        return;
    }

    MeshInfo("err_id=%d\n", evt_id);
    param =  (notify_params_t *) malloc(sizeof(notify_params_t));
    if ( param == NULL )
    {
        MeshError("%s: Malloc failed to alloc memory for thread_arg\n", __FUNCTION__);
        return;
    }
    else
    {
        memset(param, 0, sizeof(notify_params_t));
        strncpy(param->mac, pod_mac, sizeof(param->mac));
        if (evt_id < EVENT_ID_MAX)
        {
            param ->evt_id = evt_id;
        }
        else
        {
            MeshInfo("%s:invalid event id \n", __FUNCTION__);
            free(param);
            return;
        }

        if (evt_type < EVENT_TYPE_MAX)
        {
            param ->evt_type = evt_type;
        }
        else
        {
            MeshInfo("%s:invalid event type \n", __FUNCTION__);
            free(param);
            return;
        }

        err = pthread_create(&NotificationThreadId, NULL, sendNotification, (void *) param);
        if (err != 0)
        {
            MeshError("Error creating Notification thread :[%s]\n", strerror(err));
        }
        else
        {
            MeshInfo("Notification thread created Successfully\n");
        }
    }

}

bool
devinfo_getv(const char *what, char *dest, size_t destsz, bool empty_ok)
{
    char        cmd[DEVINFO_CMD_MAX];
    FILE        *f1;
    int         ret;

    if (strlen(what) > DEVINFO_MAX_LEN) {
        MeshError("devinfo_getv(%s) - Item too long, %d bytes max", what, DEVINFO_MAX_LEN);
        return false;
    }

    ret = snprintf(cmd, sizeof(cmd)-1, DEVINFO_CMD_FMT, what);
    if (ret >= (int)(sizeof(cmd)-1)) {
        MeshError("devinfo_getv(%s) - Command too long!", what);
        return false;
    }

    f1 = popen(cmd, "r");
    if (!f1) {
        MeshError("devinfo_getv(%s) - popen failed, errno = %d", what, errno);
        return false;
    }

    if (fgets(dest, destsz, f1) == NULL) {
        MeshError("devinfo_getv(%s) - reading failed, errno = %d", what, errno);
        pclose(f1);
        return false;
    }
    pclose(f1);

    while(dest[strlen(dest)-1] == '\r' || dest[strlen(dest)-1] == '\n') {
        dest[strlen(dest)-1] = '\0';
    }

    if (!empty_ok && strlen(dest) == 0) {
        return false;
    }

    return true;
}

void* sendNotification(void* data)
{
    wrp_msg_t *notif_wrp_msg = NULL;
    int retry_count = 0;
    int sendStatus = -1;
    int backoffRetryTime = 0;
    int c=2;
    char source[MAX_PARAMETERNAME_LEN/2] = {'\0'};
    cJSON *notifyPayload = cJSON_CreateObject();
    char  * stringifiedNotifyPayload = NULL;
    notify_params_t *param = NULL;
    int evt_id = 0xff;
    int evt_type = 0xff;
    char evt_id_str[12] = {'\0'};
    char evt_type_str[12] = {'\0'};
    /*char msg[512] = {'\0'};*/
    char dest[1024] = {'\0'};
    char pod_id[MAX_MAC_ADDR_LEN] = { 0 };
    char cmmac[32];

    pthread_detach(pthread_self());

    if(data)
    {
        param = (notify_params_t *) data;
        strncpy(pod_id, param->mac, sizeof(pod_id));
        if (param ->evt_id < EVENT_ID_MAX)
        {
            evt_id = param ->evt_id;
        }
        else
        {
            MeshInfo("%s:invalid event id \n", __FUNCTION__);
            goto out;
        }

        if (param ->evt_type < EVENT_TYPE_MAX)
        {
            evt_type = param ->evt_type;
        }
        else
        {
            MeshInfo("%s:invalid event type \n", __FUNCTION__);
            goto out;
        }

    }
    else
    {
        MeshInfo("%s:invalid thread_arg->data \n", __FUNCTION__);
        return NULL;
    }

    if(strlen(deviceMAC) == 0)
    {
        /* TODO: add lock as multiple thread might keep on get the cmac */
        if (!devinfo_getv(DEVINFO_CM_MAC, cmmac, sizeof(cmmac), false))
        {
            MeshError("Failed to get the deviceMAC \n");
            goto out;
        }
        else
        {
            MeshInfo("CMAC: %s\n",cmmac);
            AnscMacToLower(deviceMAC, cmmac, sizeof(deviceMAC));
            MeshInfo("deviceMAC is %s\n",deviceMAC);
        }
    }


    if(strlen(deviceMAC) == 0)
    {
        MeshError("deviceMAC is NULL, failed to send Notification\n");
    }
    else
    {
        MeshInfo("deviceMAC: %s\n",deviceMAC);
        snprintf(source, sizeof(source), "mac:%s", deviceMAC);

        if(notifyPayload != NULL)
        {
            cJSON_AddStringToObject(notifyPayload,"device_id", source);

            cJSON_AddStringToObject(notifyPayload,"pod_id", pod_id);

            if (evt_type == ERROR)
            {
                sprintf(evt_type_str, "%s", "ERROR");
            }
            else if (evt_type == INFO)
            {
                sprintf(evt_type_str, "%s", "INFO");
            }
            MeshInfo("event_type_str=%s evt_type=%d\n", evt_type_str, evt_type);
            cJSON_AddStringToObject(notifyPayload,"event_type", evt_type_str);

            sprintf(evt_id_str, "%d", evt_id);
            MeshInfo("evt_id_str=%s evt_id=%d\n", evt_id_str, evt_id);
            cJSON_AddStringToObject(notifyPayload,"event_id", evt_id_str);

            cJSON_AddStringToObject(notifyPayload,"event_msg", mesh_event[evt_id].event_string);

            stringifiedNotifyPayload = cJSON_PrintUnformatted(notifyPayload);
            MeshInfo("Notification payload %s\n",stringifiedNotifyPayload);
            cJSON_Delete(notifyPayload);
        }

        notif_wrp_msg = (wrp_msg_t *)malloc(sizeof(wrp_msg_t));
        memset(notif_wrp_msg, 0, sizeof(wrp_msg_t));
        if(notif_wrp_msg != NULL)
        {
            notif_wrp_msg ->msg_type = WRP_MSG_TYPE__EVENT;
            notif_wrp_msg ->u.event.source = strdup(source);
            MeshDebug("source: %s\n",notif_wrp_msg ->u.event.source);

            snprintf(dest,sizeof(dest),"event:mesh-agent/mac:%s/%s/%s/%d/%s",
                            deviceMAC, evt_type_str, pod_id, evt_id, mesh_event[evt_id].event_string);
            notif_wrp_msg ->u.event.dest = strdup(dest);
            MeshInfo("destination: %s\n", notif_wrp_msg ->u.event.dest);
            notif_wrp_msg->u.event.content_type = strdup(CONTENT_TYPE_JSON);
            MeshInfo("content_type is %s\n",notif_wrp_msg->u.event.content_type);
            if(stringifiedNotifyPayload != NULL)
            {
                notif_wrp_msg ->u.event.payload = (void *) stringifiedNotifyPayload;
                notif_wrp_msg ->u.event.payload_size = strlen(stringifiedNotifyPayload);
            }

            while(retry_count<=3)
            {
                backoffRetryTime = (int) pow(2, c) -1;

            MeshInfo("Before libparodus_send \n");
                sendStatus = libparodus_send(mesh_agent_instance, notif_wrp_msg );
            MeshInfo("After libparodus_send \n");

                if(sendStatus == 0)
                {
                    retry_count = 0;
                    MeshInfo("Notification successfully sent to parodus\n");
                    break;
                }
                else
                {
                    MeshError("Failed to send Notification: '%s', retrying ....\n",libparodus_strerror(sendStatus));
                    MeshInfo("sendNotification backoffRetryTime %d seconds\n", backoffRetryTime);
                    sleep(backoffRetryTime);
                    c++;
                    retry_count++;
                 }
           }
           MeshInfo("sendStatus is %d\n",sendStatus);
           wrp_free_struct (notif_wrp_msg );
       }
    }

out:
    if (param)
    {
        free(param);
    }
    return NULL;
}

const char *rdk_logger_module_fetch(void)
{
    return "LOG.RDK.MESHAGENT";
}

#endif
