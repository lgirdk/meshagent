/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
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

#include <syscfg/syscfg.h>
#include "cosa_webconfig_api.h"
#include "meshagent.h"
#include "meshsync_msgs.h"
#include "cosa_meshagent_internal.h"
#include <syscfg/syscfg.h>
#include "cosa_apis_util.h"
#include "helpers.h"
#include "mesh_rbus.h"
#include <trower-base64/base64.h>

#define TYPE(i) configs->config_data[i].type

#define VALUE_STRING(i) configs->config_data[i].value.string_value
#define VALUE_BOOLEAN(i) configs->config_data[i].value.boolean_value
#define NAME(i) configs->config_data[i].name
#define CALC_TIMEOUT_CALLBACK(blob_name) execDataMb->calcTimeout = blob_name##_calc_timeout_handler
#define EXECUTE_TIMEOUT_CALLBACK(blob_name) execDataMb->executeBlobRequest = blob_name##_execute_timeout_handler
#define ROLLBACK_TIMEOUT_CALLBACK(blob_name) execDataMb->rollbackFunc = blob_name##_rollback_timeout_handler
#define FREE_TIMEOUT_CALLBACK(blob_name) execDataMb->freeResources = blob_name##_free_timeout_handler

#define TIMEOUT_FUNC(NAME,type) NAME##_TIMEOUT(type)

#define CALC_TIMEOUT(blob_type)                                        \
    do{                                                                \
       if (blob_type == MESH){                                         \
           CALC_TIMEOUT_CALLBACK(mesh);                                \
       }                                                               \
       else if (blob_type == STEERING_PROFILE_DEFAULT){                \
           CALC_TIMEOUT_CALLBACK(steeringprofiledefaults);             \
       }                                                               \
       else if (blob_type == DEVICE){                                  \
           CALC_TIMEOUT_CALLBACK(devicetosteerprof);                   \
       }                                                               \
       else if (blob_type == CONFIGS){                                 \
           CALC_TIMEOUT_CALLBACK(mwoconfigs);                          \
       }                                                               \
       else if (blob_type == INTERFERENCE){                            \
           CALC_TIMEOUT_CALLBACK(interference);                        \
       }                                                               \
       else if (blob_type == WIFI_MOTION){                             \
           CALC_TIMEOUT_CALLBACK(wifimotionsettings);                  \
       }                                                               \
    } while (0)

#define EXECUTE_TIMEOUT(blob_type)                                     \
    do {                                                               \
       if (blob_type == MESH)                                          \
           EXECUTE_TIMEOUT_CALLBACK(mesh);                             \
       else if (blob_type == STEERING_PROFILE_DEFAULT)                 \
           EXECUTE_TIMEOUT_CALLBACK(steeringprofiledefaults);          \
       else if (blob_type == DEVICE)                                   \
           EXECUTE_TIMEOUT_CALLBACK(devicetosteerprof);                \
       else if (blob_type == CONFIGS)                                  \
           EXECUTE_TIMEOUT_CALLBACK(mwoconfigs);                       \
       else if (blob_type == INTERFERENCE)                             \
           EXECUTE_TIMEOUT_CALLBACK(interference);                     \
       else if (blob_type == WIFI_MOTION)                              \
           EXECUTE_TIMEOUT_CALLBACK(wifimotionsettings);               \
       } while (0)

#define ROLLBACK_TIMEOUT(blob_type)                                    \
    do {                                                               \
       if (blob_type == MESH)                                          \
           ROLLBACK_TIMEOUT_CALLBACK(mesh);                            \
       else if (blob_type == STEERING_PROFILE_DEFAULT)                 \
           ROLLBACK_TIMEOUT_CALLBACK(steeringprofiledefaults);         \
       else if (blob_type == DEVICE)                                   \
           ROLLBACK_TIMEOUT_CALLBACK(devicetosteerprof);               \
       else if (blob_type == CONFIGS)                                  \
           ROLLBACK_TIMEOUT_CALLBACK(mwoconfigs);                      \
       else if (blob_type == INTERFERENCE)                             \
           ROLLBACK_TIMEOUT_CALLBACK(interference);                    \
       else if (blob_type == WIFI_MOTION)                              \
           ROLLBACK_TIMEOUT_CALLBACK(wifimotionsettings);              \
       } while (0)

#define FREE_TIMEOUT(blob_type)                                        \
    do {                                                               \
       if (blob_type == MESH)                                          \
           FREE_TIMEOUT_CALLBACK(mesh);                                \
       else if (blob_type == STEERING_PROFILE_DEFAULT)                 \
           FREE_TIMEOUT_CALLBACK(steeringprofiledefaults);             \
       else if (blob_type == DEVICE)                                   \
           FREE_TIMEOUT_CALLBACK(devicetosteerprof);                   \
       else if (blob_type == CONFIGS)                                  \
           FREE_TIMEOUT_CALLBACK(mwoconfigs);                          \
       else if (blob_type == INTERFERENCE)                             \
           FREE_TIMEOUT_CALLBACK(interference);                        \
       else if (blob_type == WIFI_MOTION)                              \
           FREE_TIMEOUT_CALLBACK(wifimotionsettings);                  \
       } while (0)

pErr mesh_execute_timeout_handler(void *Data);
size_t mesh_calc_timeout_handler(size_t numOfEntries);
int mesh_rollback_timeout_handler();
void mesh_free_timeout_handler(void *arg);

pErr steeringprofiledefaults_execute_timeout_handler(void *Data);
size_t steeringprofiledefaults_calc_timeout_handler (size_t count);
int steeringprofiledefaults_rollback_timeout_handler();
void steeringprofiledefaults_free_timeout_handler(void *arg);

pErr devicetosteerprof_execute_timeout_handler(void *Data);
size_t devicetosteerprof_calc_timeout_handler (size_t count);
int devicetosteerprof_rollback_timeout_handler();
void devicetosteerprof_free_timeout_handler(void *arg);

pErr mwoconfigs_execute_timeout_handler(void *Data);
size_t mwoconfigs_calc_timeout_handler (size_t count);
int mwoconfigs_rollback_timeout_handler();
void mwoconfigs_free_timeout_handler(void *arg);

pErr interference_execute_timeout_handler(void *Data);
size_t interference_calc_timeout_handler (size_t count);
int interference_rollback_timeout_handler();
void interference_free_timeout_handler(void *arg);

pErr wifimotionsettings_execute_timeout_handler(void *Data);
size_t wifimotionsettings_calc_timeout_handler (size_t count);
int wifimotionsettings_rollback_timeout_handler();
void wifimotionsettings_free_timeout_handler(void *arg);

typedef size_t (*calcTimeout_fn_t) (size_t);
typedef pErr (*executeBlobRequest_fn_t) (void*);
typedef int (*rollbackFunc_fn_t) ();
typedef void (*freeResources_fn_t) (void *);

extern rbusHandle_t handle;
static t_cache mb_cache;
static t_cache mb_cache_bkup;

const char meshService[] = "meshwifi";
extern MeshSync_MsgItem meshSyncMsgArr[];
extern COSA_DATAMODEL_MESHAGENT* g_pMeshAgent;

void Mesh_EBCleanup();

bool push_blob_request(char * name, void *data, uint32_t version, uint16_t transaction_id,eBlobType blob_type)
{
    bool ret = true;
    execData *execDataMb = NULL ;

    execDataMb = (execData*) malloc (sizeof(execData));

    if ( execDataMb != NULL )
    {
        memset(execDataMb, 0, sizeof(execData));
        execDataMb->txid = transaction_id;
        execDataMb->version = version;
        strncpy(execDataMb->subdoc_name,name,sizeof(execDataMb->subdoc_name)-1);
        execDataMb->user_data = (void*) data;
        TIMEOUT_FUNC(CALC,blob_type);
        TIMEOUT_FUNC(EXECUTE,blob_type);
        TIMEOUT_FUNC(ROLLBACK,blob_type);
        TIMEOUT_FUNC(FREE,blob_type);
        PushBlobRequest(execDataMb);
        MeshInfo("PushBlobRequest complete for %s\n",name);
    }
    else
    {
        MeshInfo("execData memory allocation failed\n");
        ret = false;
    }
    return ret;
}

void mesh_blob_dump(meshbackhauldoc_t *mb)
{
    MeshInfo("Mesh configuration received\n");
    MeshInfo("mb->mesh_enable is %s\n", (1 == mb->mesh_enable)?"true":"false");
    MeshInfo("mb->ethernetbackhaul_enable is %s\n", (1 == mb->ethernetbackhaul_enable)?"true":"false");
    MeshInfo("mb->subdoc_name is %s\n", mb->subdoc_name);
    MeshInfo("mb->version is %lu\n", (unsigned long)mb->version);
    MeshInfo("mb->transaction_id is %d\n", mb->transaction_id);
}

void wfm_blob_dump(wfm_doc_t *wfm)
{
    save_wfm_settings_tofile(wfm);
    MeshInfo("Wifi Motion configuration received\n");
    MeshInfo("wfm->wfm_enable is %s\n", (1 == wfm->wfm_enable)?"true":"false");
    MeshInfo("wfm->subdoc_name is %s\n", wfm->subdoc_name);
    MeshInfo("wfm->version is %lu\n", (unsigned long)wfm->version);
    MeshInfo("wfm->transaction_id is %d\n", wfm->transaction_id);
}

void steeringprofile_blob_dump(sp_doc_t *sp)
{
    save_steering_profile_tofile(sp);
    MeshInfo("Steering profile received\n");
    MeshInfo("The transaction id is %d\n", sp->transaction_id);
    MeshInfo("The version is %lu\n", (long)sp->version);
    MeshInfo("The subdoc_name is %s\n", sp->subdoc_name);
}

void deviceprofile_blob_dump(dp_doc_t *dp)
{
    save_device_profile_tofile(dp);
    MeshInfo("Device profile received\n");
    MeshInfo("The transaction id is %d\n", dp->transaction_id);
    MeshInfo("The version is %lu\n", (long)dp->version);
    MeshInfo("The subdoc_name is %s\n", dp->subdoc_name);
}

void configs_blob_dump(configs_doc_t *configs)
{
    MeshInfo("mwoconfigs blob received\n");
    MeshInfo("The transaction id is %d\n", configs->transaction_id);
    MeshInfo("The version is %lu\n", (long)configs->version);
    MeshInfo("The subdoc_name is %s\n", configs->subdoc_name);
}

void ai_blob_dump(ai_doc_t *ai)
{
    save_ai_profile_tofile(ai);
    MeshInfo("interference blob received\n");
    MeshInfo("The transaction id is %d\n", ai->transaction_id);
    MeshInfo("The version is %lu\n", (long)ai->version);
    MeshInfo("The subdoc_name is %s\n", ai->subdoc_name);
}

bool  mesh_msgpack_decode(char* pString, int decode_size, eBlobType type)
{
    char * decodeMsg =NULL;
    int decodeMsgSize =0;
    int size =0;
    bool ret = true;

    msgpack_zone mempool;
    msgpack_object deserialized;
    msgpack_unpack_return unpack_ret;
    decodeMsgSize = b64_get_decoded_buffer_size(strlen(pString));
    decodeMsg = (char *) malloc(sizeof(char) * decodeMsgSize);
    size = b64_decode( pString, strlen(pString), decodeMsg );
    MeshInfo("base64 decoded data contains %d bytes\n",size);

    msgpack_zone_init(&mempool, decode_size);
    unpack_ret = msgpack_unpack(decodeMsg, size, NULL, &mempool, &deserialized);

    switch(unpack_ret)
    {
        case MSGPACK_UNPACK_SUCCESS:
            MeshInfo("MSGPACK_UNPACK_SUCCESS :%d\n",unpack_ret);
            break;
        case MSGPACK_UNPACK_EXTRA_BYTES:
            MeshInfo("MSGPACK_UNPACK_EXTRA_BYTES :%d\n",unpack_ret);
            break;
        case MSGPACK_UNPACK_CONTINUE:
            MeshInfo("MSGPACK_UNPACK_CONTINUE :%d\n",unpack_ret);
            break;
        case MSGPACK_UNPACK_PARSE_ERROR:
            MeshInfo("MSGPACK_UNPACK_PARSE_ERROR :%d\n",unpack_ret);
            break;
        case MSGPACK_UNPACK_NOMEM_ERROR:
            MeshInfo("MSGPACK_UNPACK_NOMEM_ERROR :%d\n",unpack_ret);
            break;
        default:
            MeshInfo("Message Pack decode failed with error: %d\n", unpack_ret);
    }

    msgpack_zone_destroy(&mempool);
    MeshInfo("End message pack decode\n");
    if(unpack_ret == MSGPACK_UNPACK_SUCCESS)
    {
        if (type == MESH)
        {
            meshbackhauldoc_t *mb;
            mb = (meshbackhauldoc_t *) blob_data_convert( decodeMsg, size+1, MESH );
            if (NULL != mb)
            {
                mesh_blob_dump(mb);
                if(!push_blob_request("mesh",mb,mb->version,mb->transaction_id,MESH))
                {
                    meshbackhauldoc_destroy( mb );
                    ret = false;
                }
            }
            else
            {
                MeshInfo("meshbackhauldoc_convert failed\n");
                ret =false;
            }
        }
        else if (type == STEERING_PROFILE_DEFAULT)
        {
            sp_doc_t *sp = NULL;
            sp = (sp_doc_t *) blob_data_convert( decodeMsg, size+1,STEERING_PROFILE_DEFAULT);
            if (NULL != sp)
            {
                steeringprofile_blob_dump(sp);
                if(!push_blob_request("meshsteeringprofiles",sp,sp->version,sp->transaction_id,STEERING_PROFILE_DEFAULT))
                {
                    destroy_spsteeringdoc( (void *)sp);
                    ret = FALSE;
                }
                else
                {
                    char* payload = steering_profile_event_data_get();
                    if (payload)
                    {
                        publishRBUSEvent(MWO_TOS_CONFIGURATION, (void *)payload,handle);
                        free(payload);
                        g_pMeshAgent->meshSteeringProfileDefault = true;
                    }
                }
            }
            else
            {
                MeshInfo("steering_profile_convert failed\n");
                ret =FALSE;
            }
        }
        else if (type == DEVICE)
        {
            dp_doc_t *dp = NULL;
            dp = (dp_doc_t *) blob_data_convert( decodeMsg, size+1,DEVICE);
            if (NULL != dp)
            {
                deviceprofile_blob_dump(dp);
                if(!push_blob_request("clienttosteeringprofile",dp,dp->version,dp->transaction_id,DEVICE))
                {
                    destroy_dpdoc( (void *)dp);
                    ret = FALSE;
                }
                else
                {
                    char* payload = client_profile_event_data_get();
                    if (payload)
                    {
                        publishRBUSEvent(MWO_CLIENT_TO_PROFILE_MAP_EVENT, (void *)payload,handle);
                        free(payload);
                        g_pMeshAgent->meshClientProfileReceived = true;
                    }
                }
            }
            else
            {
                MeshInfo("device_profileconvert failed\n");
                ret = FALSE;
            }
        }
        else if (type == CONFIGS)
        {
            configs_doc_t *configs = NULL;
            configs = (configs_doc_t *) blob_data_convert( decodeMsg, size+1,CONFIGS);
            if (NULL != configs)
            {
                configs_blob_dump(configs);
                if(!push_blob_request("mwoconfigs",configs,configs->version,configs->transaction_id,CONFIGS))
                {
                    destroy_configsdoc((void *)configs);
                    ret = FALSE;
                }
            }
            else
            {
                MeshInfo("mwoconfigs failed\n");
                ret = FALSE;
            }
        }
        else if (type == INTERFERENCE)
        {
            ai_doc_t *ai = NULL;
            ai = (ai_doc_t *) blob_data_convert( decodeMsg, size+1,INTERFERENCE);
            if (NULL != ai)
            {
                ai_blob_dump(ai);
                if(!push_blob_request("interference",ai,ai->version,ai->transaction_id,INTERFERENCE))
                {
                    destroy_aidoc((void *)ai);
                    ret = FALSE;
                }
            }
        }
        else if (type == WIFI_MOTION)
        {
            wfm_doc_t *wfm = NULL;
            wfm = (wfm_doc_t *) blob_data_convert( decodeMsg, size+1,WIFI_MOTION);
            if (NULL != wfm)
            {
                wfm_blob_dump(wfm);
                if(!push_blob_request("wifimotionsettings",wfm,wfm->version,wfm->transaction_id,WIFI_MOTION))
                {
                    destroy_wfmdoc((void *)wfm);
                    ret = FALSE;
                }
                else
                {
                    g_pMeshAgent->meshwfmSettingsReceived = true;
                    char* payload = wfm_event_data_get();
                    if (payload)
                    {
                        publishRBUSEvent(WFM_CONFIGURATION, (void *)payload,handle);
                        free(payload);
                    }
                }
            }
            else
            {
                MeshInfo("wifimotionsettings failed\n");
                ret = FALSE;
            }
        }
    }
    else
    {
        MeshInfo("Corrupted Mesh value\n");
        ret =false;
    }

    if ( decodeMsg )
    {
        free(decodeMsg);
        decodeMsg = NULL;
    }

    return ret;
}

bool mesh_set_enabled(bool enable)
{
    // MeshInfo("Entering into %s\n",__FUNCTION__);
    unsigned char bit_mask = 0;

    if(enable)
        bit_mask = bit_mask | 0x02;

    // If the enable value is different or this is during setup - make it happen.
    if (Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr) != enable)
    {
        meshSetSyscfg(enable, true);
        handleMeshEnable((void *)bit_mask);
    }

    return getMeshErrorCode();
}

int validate_mesh_enable( bool  mesh_enable , bool eth_backhaul_enable )
{
    char rdk_dcs[2][128];
    char vendor_dcs[2][128];
    int i=0;
    int ret = MB_OK;

    strncpy(rdk_dcs[0], "Device.WiFi.Radio.1.X_RDKCENTRAL-COM_DCSEnable", 128);
    strncpy(rdk_dcs[1], "Device.WiFi.Radio.2.X_RDKCENTRAL-COM_DCSEnable", 128);
    strncpy(vendor_dcs[0], "Device.WiFi.Radio.1.X_COMCAST-COM_DCSEnable", 128);
    strncpy(vendor_dcs[1], "Device.WiFi.Radio.2.X_COMCAST-COM_DCSEnable", 128);
    
    if(mesh_enable)
    {
        if(is_bridge_mode_enabled())
        {
            MeshError("MESH_ERROR:Fail to enable Mesh when Bridge mode is on\n");
            ret = MB_ERROR_BRIDGE_MODE_ENABLED;
        }
        if(is_radio_enabled(rdk_dcs[0],rdk_dcs[1])) {
            for(i=0; i<2; i++) {
                if(rdk_dcs[i][0]!=0 && set_wifi_boolean_enable(rdk_dcs[i], "false")==FALSE) {
                    MeshError("MESH_ERROR:Fail to enable Mesh because fail to turn off %s\n", rdk_dcs[i]);
                    ret = MB_ERROR_RADIO_OFF;
                }
            }
        }
        if(is_radio_enabled(vendor_dcs[0],vendor_dcs[1])) {
            for(i=0; i<2; i++) {
                if(vendor_dcs[i][0]!=0 && set_wifi_boolean_enable(vendor_dcs[i], "false")==FALSE) {
                    MeshError("MESH_ERROR:Fail to enable Mesh because fail to turn off %s\n", vendor_dcs[i]);
                    ret = MB_ERROR_RADIO_OFF;
                }
            }
        }
    }
    else {
        MeshInfo("Mesh disabled, Disable Ethernet bhaul if enabled\n");
        if( eth_backhaul_enable )
        {
            MeshInfo("Send Eth Bhaul disable notification to plume\n");
            Mesh_EBCleanup();
            Mesh_SendEthernetMac("00:00:00:00:00:00");
        }
    }

    return ret;
}

/* API to get the subdoc version */

uint32_t getBlobVersion(char* subdoc)
{

    char subdoc_ver[64] = {0}, buf[72] = {0};
    snprintf(buf,sizeof(buf),"%s_version",subdoc);
    if ( syscfg_get( NULL, buf, subdoc_ver, sizeof(subdoc_ver)) == 0 )
    {
        int version = atoi(subdoc_ver);
        return (uint32_t)version;
    }
    return 0;
}

/* API to update the subdoc version */
int setBlobVersion(char* subdoc,uint32_t version)
{

    char subdoc_ver[64] = {0}, buf[72] = {0};
    snprintf(subdoc_ver,sizeof(subdoc_ver),"%u",version);
    snprintf(buf,sizeof(buf),"%s_version",subdoc);
    if(syscfg_set_commit(NULL,buf,subdoc_ver) != 0)
    {
        MeshError("syscfg_set failed\n");
        return -1;
    }
    return 0;
}

/* API to register all the supported subdocs , versionGet and versionSet are callback functions to get and set the subdoc versions in db */

void webConfigFrameworkInit()
{
    char *sub_docs[SUBDOC_COUNT+1]= {"mesh","meshsteeringprofiles","clienttosteeringprofile","wifistatsconfig","mwoconfigs","interference","wifimotionsettings",(char *) 0 };
    int i;

    blobRegInfo *blobData;
    blobData = (blobRegInfo*) malloc(SUBDOC_COUNT * sizeof(blobRegInfo));
    memset(blobData, 0, SUBDOC_COUNT * sizeof(blobRegInfo));
    blobRegInfo *blobDataPointer = blobData;
    for (i=0 ; i < SUBDOC_COUNT ; i++ )
    {
        strncpy( blobDataPointer->subdoc_name, sub_docs[i], sizeof(blobDataPointer->subdoc_name)-1);
        blobDataPointer++;
    }
    blobDataPointer = blobData ;
    getVersion versionGet = getBlobVersion;
    setVersion versionSet = setBlobVersion;
    register_sub_docs(blobData,SUBDOC_COUNT,versionGet,versionSet);
}

/* API to clear the buffer */
void clear_mb_cache(t_cache *tmp_mb_cache)
{
    tmp_mb_cache->mesh_enable = false;
    tmp_mb_cache->ethernetbackhaul_enable = false;
}

/* API to print cache */
void print_mb_cache(t_cache *tmp_mb_cache)
{
    MeshInfo("mb->mesh_enable is %s\n", (1 == tmp_mb_cache->mesh_enable)?"true":"false");
    MeshInfo("mb->ethernetbackhaul_enable is %s\n", (1 == tmp_mb_cache->ethernetbackhaul_enable)?"true":"false");

}

/* API to back up the cache */
void backup_mb_cache(t_cache *tmp_mb_cache,t_cache *tmp_mb_cache_bkup)
{
    tmp_mb_cache_bkup->mesh_enable = tmp_mb_cache->mesh_enable;
    tmp_mb_cache_bkup->ethernetbackhaul_enable = tmp_mb_cache->ethernetbackhaul_enable;
}

/* API to apply mesh  requests to DB */
int apply_mb_cache_ToDB(t_cache *cache)
{
    int ret = MB_OK;
    
    ret = mesh_set_enabled(cache->mesh_enable);
    if (ret == MB_OK)
    {
        Mesh_SetMeshEthBhaul(cache->ethernetbackhaul_enable, false, true);
    }

    return ret;
}

/* Read blob entries into a cache */
int set_meshbackhaul_conf(meshbackhauldoc_t *mb,t_cache *cache)
{
    int ret = MB_OK;
 
    ret = validate_mesh_enable (mb->mesh_enable, mb->ethernetbackhaul_enable );
    if ( ret == MB_OK )
    {
        cache->mesh_enable = mb->mesh_enable;
        cache->ethernetbackhaul_enable = mb->ethernetbackhaul_enable;
    }
    return ret;
}

/* Initialize cache , this API will be called once in boot up */
void init_mb_cache(t_cache *tmp_mb_cache)
{
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;

    tmp_mb_cache->mesh_enable = pMyObject->meshEnable;
    tmp_mb_cache->ethernetbackhaul_enable = pMyObject->PodEthernetBackhaulEnable;
}

size_t devicetosteerprof_calc_timeout_handler (size_t count)
{
    MeshInfo("In devicetosteerprof_calc_timeout_handler numOfEntried = %lu\n", (long unsigned int) count);
    return MESH_DEFAULT_TIMEOUT;
}

pErr devicetosteerprof_execute_timeout_handler(void *Data)
{
    dp_doc_t *dp = (dp_doc_t *)Data;
    pErr execRetVal = NULL;

    if (dp == NULL)
    {
        MeshError("%s : Data is empty\n",__FUNCTION__);
        return execRetVal;
    }

    execRetVal = (pErr) malloc (sizeof(Err));
    if (execRetVal == NULL )
    {
        MeshError("%s : malloc failed\n",__FUNCTION__);
        return execRetVal;
    }

    memset(execRetVal,0,sizeof(Err));
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg) - 1, "%s","enabled");
    return execRetVal;
}

int devicetosteerprof_rollback_timeout_handler()
{
    // return 0 to notify framework when rollback is success
    MeshInfo("Entering %s \n",__FUNCTION__);
    return 0 ;
}

void devicetosteerprof_free_timeout_handler(void *arg)
{
    MeshInfo("Entering %s \n",__FUNCTION__);
    execData *blob_exec_data  = (execData*) arg;

    if ( blob_exec_data != NULL )
    {
        dp_doc_t *rpm = (dp_doc_t *) blob_exec_data->user_data;
        if ( rpm != NULL )
        {
            destroy_dpdoc(rpm);
        }
        free(blob_exec_data);
        blob_exec_data = NULL ;
    }
    return;
}

size_t interference_calc_timeout_handler (size_t count)
{
    MeshInfo("In interference_calc_timeout_handler numOfEntried = %lu\n", (long unsigned int) count);
    return MESH_DEFAULT_TIMEOUT;
}

pErr interference_execute_timeout_handler(void *Data)
{
    ai_doc_t *ai = (ai_doc_t *)Data;
    pErr execRetVal = NULL;

    if (ai == NULL)
         MeshError("%s : malloc failed\n",__FUNCTION__);

    execRetVal = (pErr) malloc (sizeof(Err));
    if (execRetVal == NULL )
    {
        MeshError("%s : malloc failed\n",__FUNCTION__);
        return execRetVal;
    }

    memset(execRetVal,0,sizeof(Err));
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg) - 1, "%s","enabled");
    return execRetVal;
}

int interference_rollback_timeout_handler()
{
    // return 0 to notify framework when rollback is success
    MeshInfo(" Entering %s \n",__FUNCTION__);
    return 0 ;
}

void interference_free_timeout_handler(void *arg)
{
    MeshInfo(" Entering %s \n",__FUNCTION__);
    execData *blob_exec_data  = (execData*) arg;

    if ( blob_exec_data != NULL )
    {
        ai_doc_t *ai = (ai_doc_t *) blob_exec_data->user_data;
        if ( ai != NULL )
        {
            destroy_aidoc(ai);
        }
        free(blob_exec_data);
        blob_exec_data = NULL ;
    }
    return;
}

pErr mwoconfigs_execute_timeout_handler(void *Data)
{
    int i = 0;
    configs_doc_t *configs = (configs_doc_t *)Data;
    pErr execRetVal = NULL;

    if (configs == NULL)
    {
        MeshError("%s : Data is empty\n",__FUNCTION__);
        return execRetVal;
    }

    execRetVal = (pErr) malloc (sizeof(Err));
    if (execRetVal == NULL )
    {
        MeshError("%s : malloc failed\n",__FUNCTION__);
        return execRetVal;
    }

    //TODO:set syscfg offline_mqtt_broker, 160_mhz_support
    MeshInfo("configs count = %d\n",configs->count);
    for ( i = 0 ;i < configs->count; i++ )
    {
       if (NAME(i) && (strncmp("offline_mqtt_broker",NAME(i), sizeof("offline_mqtt_broker")) == 0))
       {
           if ((TYPE(i) ==  TYPE_STRING) && (VALUE_STRING(i)))
               Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_OPT_ENABLE_MODE_BROKER_URL].sysStr, VALUE_STRING(i), false);
       }
       else if (NAME(i) && (strncmp("offline_mqtt_port",NAME(i), sizeof("offline_mqtt_port")) == 0))
       {
           if ((TYPE(i) ==  TYPE_STRING) && (VALUE_STRING(i)))
               Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_OPT_ENABLE_MODE_BROKER_PORT].sysStr, VALUE_STRING(i), false);
       }
       else if (NAME(i) && (strncmp("offline_mqtt_topic",NAME(i), sizeof("offline_mqtt_topic")) == 0))
       {
           if ((TYPE(i) ==  TYPE_STRING) && (VALUE_STRING(i)))
               Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_OPT_ENABLE_MODE_BROKER_TOPIC].sysStr, VALUE_STRING(i), false);
       }
    }
    memset(execRetVal,0,sizeof(Err));
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg) - 1, "%s","enabled");
    return execRetVal;
}

int mwoconfigs_rollback_timeout_handler()
{
    // return 0 to notify framework when rollback is success
    MeshInfo(" Entering %s \n",__FUNCTION__);
    return 0;
}

size_t mwoconfigs_calc_timeout_handler (size_t count)
{
    MeshInfo("In mwoconfigs_calc_timeout_handler numOfEntried = %lu\n", (long unsigned int) count);
    return MESH_DEFAULT_TIMEOUT;
}

void mwoconfigs_free_timeout_handler(void *arg)
{
    MeshInfo(" Entering %s \n",__FUNCTION__);
    execData *blob_exec_data  = (execData*) arg;

    if ( blob_exec_data != NULL )
    {
        configs_doc_t *rpm = (configs_doc_t *) blob_exec_data->user_data;
        if ( rpm != NULL )
        {
            destroy_configsdoc(rpm);
        }
        free(blob_exec_data);
        blob_exec_data = NULL ;
    }
    return;
}

/* Callback function to rollback when wfm  blob execution fails */
int wifimotionsettings_rollback_timeout_handler()
{
    // return 0 to notify framework when rollback is success
    MeshInfo(" Entering %s \n",__FUNCTION__);

    return 0 ;
}

void wifimotionsettings_free_timeout_handler(void *arg)
{
    MeshInfo(" Entering %s \n",__FUNCTION__);
    execData *blob_exec_data  = (execData*) arg;

    if ( blob_exec_data != NULL )
    {
        wfm_doc_t *wfm = (wfm_doc_t *) blob_exec_data->user_data;
        if ( wfm != NULL )
        {
            destroy_wfmdoc( wfm );
        }
        free(blob_exec_data);
        blob_exec_data = NULL ;
    }
}

/**
 *  Function to calculate timeout value for executing the blob
 *
 *  @param numOfEntries Number of Entries of blob
 *
 * returns timeout value
 */
size_t wifimotionsettings_calc_timeout_handler(size_t numOfEntries)
{
    MeshInfo("In wfm_calc_timeout_handler numOfEntried = %lu\n", (long unsigned int) numOfEntries);
    return MESH_DEFAULT_TIMEOUT;
}

pErr wifimotionsettings_execute_timeout_handler(void *Data)
{
    wfm_doc_t *wfm = (wfm_doc_t *)Data;
    pErr execRetVal = NULL;

    if (wfm == NULL)
    {
        MeshError("%s : Data is empty\n",__FUNCTION__);
        return execRetVal;
    }

    execRetVal = (pErr) malloc (sizeof(Err));
    if (execRetVal == NULL )
    {
        MeshError("%s : malloc failed\n",__FUNCTION__);
        return execRetVal;
    }

    memset(execRetVal,0,sizeof(Err));
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg) - 1, "%s","enabled");
    return execRetVal;
}

pErr steeringprofiledefaults_execute_timeout_handler(void *data)
{
    sp_doc_t *sp = (sp_doc_t *)data;
    pErr execRetVal = NULL;

    if (sp == NULL)
    {
        MeshError("%s : Data is empty\n",__FUNCTION__);
        return execRetVal;
    }

    execRetVal = (pErr) malloc (sizeof(Err));
    if (execRetVal == NULL )
    {
        MeshError("%s : malloc failed\n",__FUNCTION__);
        return execRetVal;
    }

    memset(execRetVal,0,sizeof(Err));
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg) - 1, "%s","enabled");
    return execRetVal;
}

size_t steeringprofiledefaults_calc_timeout_handler (size_t count)
{
    MeshInfo("In steeringprofiledefaults_calc_timeout_handler numOfEntried = %lu\n", (long unsigned int) count);
    return MESH_DEFAULT_TIMEOUT;
}

int steeringprofiledefaults_rollback_timeout_handler()
{
    // return 0 to notify framework when rollback is success
    MeshInfo(" Entering %s \n",__FUNCTION__);
    return 0 ;
}
void steeringprofiledefaults_free_timeout_handler(void *arg)
{
    MeshInfo(" Entering %s \n",__FUNCTION__);
    execData *blob_exec_data  = (execData*) arg;

    if ( blob_exec_data != NULL )
    {
        sp_defaultdoc_t *rpm = (sp_defaultdoc_t *) blob_exec_data->user_data;
        if ( rpm != NULL )
        {
            destroy_spsteeringdoc(rpm);
        }
        free(blob_exec_data);
        blob_exec_data = NULL ;
    }
    return;
}

/* CallBack API to execute Mesh Blob request */
pErr mesh_execute_timeout_handler(void *Data)
{
    int ret;
    pErr execRetVal = NULL;

    execRetVal = (pErr) malloc (sizeof(Err));
    if (execRetVal == NULL )
    {
        MeshError("%s : Data is empty\n",__FUNCTION__);
        return execRetVal;
    }

    memset(execRetVal,0,sizeof(Err));
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    meshbackhauldoc_t *mb = (meshbackhauldoc_t *) Data ;
    MeshInfo("Mesh configurartion recieved\n");
    backup_mb_cache(&mb_cache,&mb_cache_bkup);

    ret  = set_meshbackhaul_conf(mb,&mb_cache);
    if ( MB_OK != ret )
    {
        if ( MB_ERROR_BRIDGE_MODE_ENABLED == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Bridge mode Enabled\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_BRIDGE_MODE_ENABLED;

            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Bridge mode Enabled",sizeof(execRetVal->ErrorMsg)-1);
        }
        else if ( MB_ERROR_RADIO_OFF == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Radio is off\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_RADIO_OFF;
            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Radio is off",sizeof(execRetVal->ErrorMsg)-1);
        }
        backup_mb_cache(&mb_cache_bkup,&mb_cache);
        return execRetVal;
    }
    ret = apply_mb_cache_ToDB(&mb_cache);
    if ( MB_OK != ret ) 
    {
        if ( MB_ERROR_BANDSTEERING_ENABLED == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Bandsteering Enabled\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_BANDSTEERING_ENABLED;

            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Bandsteerin Enabled",sizeof(execRetVal->ErrorMsg)-1);
        }
        else if ( MB_ERROR_MESH_SERVICE_START_FAIL == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Mesh service start failed\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_MESH_SERVICE_START_FAIL;
            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Mesh service start failed",sizeof(execRetVal->ErrorMsg)-1);
        }
        else if (MB_ERROR_MESH_SERVICE_STOP_FAIL == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Mesh service stop failed\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_MESH_SERVICE_STOP_FAIL;
            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Mesh service stop failed",sizeof(execRetVal->ErrorMsg)-1);
        }
        else if (MB_ERROR_PRECONDITION_FAILED == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Precondition failed\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_PRECONDITION_FAILED;
            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Mesh precondition failed",sizeof(execRetVal->ErrorMsg)-1);
        }
        backup_mb_cache(&mb_cache_bkup,&mb_cache);
        return execRetVal;
    }

    MeshInfo("Mesh configuration applied\n");
    MeshInfo("mb->mesh_enable is %s\n", (1 == mb->mesh_enable)?"true":"false");
    MeshInfo("mb->ethernetbackhaul_enable is %s\n", (1 == mb->ethernetbackhaul_enable)?"true":"false");
    snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg) - 1, "%s", (mb->mesh_enable?"enabled":"disabled"));

    return execRetVal;

}

bool is_cash_matches_db (const char * param)
{
    bool ret = true;
    int value;
    char buffer[10]={0};

    syscfg_get( NULL, param, buffer, sizeof(buffer));
    value = (0 == strcmp (buffer, "true"))?1:0;
    if ( value != mb_cache_bkup.mesh_enable ) 
    {
        ret = false;
    }

    return ret;
}
/* Callback function to rollback when mesh  blob execution fails */
int mesh_rollback_timeout_handler()
{
    // return 0 to notify framework when rollback is success
    MeshInfo(" Entering %s \n",__FUNCTION__);

    int ret = 0;

    if (!is_cash_matches_db ("mesh_enable"))
    {
        apply_mb_cache_ToDB(&mb_cache_bkup);
        backup_mb_cache(&mb_cache_bkup,&mb_cache);
    }

    return ret ;
}

void mesh_free_timeout_handler(void *arg)
{
    MeshInfo(" Entering %s \n",__FUNCTION__);
    execData *blob_exec_data  = (execData*) arg;

    if ( blob_exec_data != NULL )
    {
        meshbackhauldoc_t *rpm = (meshbackhauldoc_t *) blob_exec_data->user_data;
        if ( rpm != NULL )
        {
            meshbackhauldoc_destroy( rpm );
        }
        free(blob_exec_data);
        blob_exec_data = NULL ;
    }
}

/**
 *  Function to calculate timeout value for executing the blob
 *
 *  @param numOfEntries Number of Entries of blob
 *
 * returns timeout value
 */
size_t mesh_calc_timeout_handler(size_t numOfEntries)
{
    MeshInfo("In webconf_Mesh_Timeout_Handler numOfEntried = %lu\n", (long unsigned int) numOfEntries);
    return MESH_DEFAULT_TIMEOUT;
}

