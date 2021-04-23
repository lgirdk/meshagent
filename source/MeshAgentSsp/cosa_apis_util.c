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

#ifndef _RDKB_MESH_UTILS_C_
#define _RDKB_MESH_UTILS_C_

/*
 * @file cosa_apis_util.c
 * @brief Mesh Agent Utilities
 *
 */
#include <errno.h>
#include <stdio.h>
#include <syscfg/syscfg.h>
#include <sysevent/sysevent.h>
#include <unistd.h>
#include "ccsp_trace.h"
#include "cosa_apis_util.h"
#include "meshagent.h"

extern int sysevent_fd_gs;
extern token_t sysevent_token_gs;

const char *svcagt_systemctl_cmd = "systemctl";

/**************************************************************************/
/*! \fn static STATUS Mesh_SyseventGetInt
 **************************************************************************
 *  \brief Get sysevent Integer Value
 *  \return int/-1
 **************************************************************************/
int Mesh_SyseventGetInt(const char *name)
{
  
   /* Coverity Issue Fix - CID:72888  : UnInitialised Variable */  
   unsigned char out_value[20] = {0};
   
   sysevent_get(sysevent_fd_gs, sysevent_token_gs, name, out_value,sizeof(out_value));
   if(out_value[0] != '\0')
   {
      return atoi(out_value);
   }
   else
   {
      MeshInfo(("sysevent_get failed\n"));
      return -1;
   }
}

/**************************************************************************/
/*! \fn static STATUS Mesh_SyseventSetInt
 **************************************************************************
 *  \brief Set sysevent Integer Value
 *  \return 0:success, <0: failure
 **************************************************************************/
int Mesh_SyseventSetInt(const char *name, int int_value)
{
   unsigned char value[20] = {0};
   sprintf(value, "%d", int_value);
   return sysevent_set(sysevent_fd_gs, sysevent_token_gs, name, value, sizeof(value));
}

/**************************************************************************/
/*! \fn static STATUS Mesh_SyseventGetInt
 **************************************************************************
 *  \brief Get sysevent Integer Value
 *  \return int/-1
 **************************************************************************/
int Mesh_SyseventGetStr(const char *name, unsigned char *out_value, int outbufsz)
{
    sysevent_get(sysevent_fd_gs, sysevent_token_gs, name, out_value, outbufsz);
    if(out_value[0] != '\0')
        return 0;
    else
        return -1;
}

int Mesh_SyseventSetStr(const char *name, unsigned char *value, int bufsz, bool toArm)
{
    int retVal = sysevent_set(sysevent_fd_gs, sysevent_token_gs, name, value, bufsz);

#if defined(_COSA_INTEL_USG_ATOM_)
    if (toArm)
    {
        // Send to ARM
        #define DATA_SIZE 1024
        char cmd2[DATA_SIZE] = {0};
        sprintf(cmd2, "rpcclient2 \"sysevent set %s \'%s\';\"",  name, value);
        system(cmd2);
    }
#endif

    return retVal;
}


/**************************************************************************/
/*! \fn static STATUS G_SysCfgGetInt
 **************************************************************************
 *  \brief Get Syscfg Integer Value
 *  \return int/-1
 **************************************************************************/
int Mesh_SysCfgGetInt(const char *name)
{
   unsigned char out_value[20] = {0};
   
   if (!syscfg_get(NULL, name, out_value, sizeof(out_value)))
   {
      return atoi(out_value);
   }
   else
   {
      MeshInfo(("syscfg_get failed\n"));
      return -1;
   }
}

/**************************************************************************/
/*! \fn static STATUS GWP_SysCfgSetInt
 **************************************************************************
 *  \brief Set Syscfg Integer Value
 *  \return 0:success, <0: failure
 **************************************************************************/
int Mesh_SysCfgSetInt(const char *name, int int_value)
{
   unsigned char value[20] = {0};
   
   int retval=0;
   sprintf(value, "%d", int_value);
   if ((retval = syscfg_set(NULL, name, value)) == 0)
   {
       syscfg_commit();
   }

   return retval;
}

int Mesh_SysCfgGetStr(const char *name, unsigned char *out_value, int outbufsz)
{
   return syscfg_get(NULL, name, out_value, outbufsz);
}

int Mesh_SysCfgSetStr(const char *name, unsigned char *str_value, bool toArm)
{
   int retval = 0;
   if ((retval = syscfg_set(NULL, name, str_value)) == 0) {
      retval = syscfg_commit();
   }

#if defined(_COSA_INTEL_USG_ATOM_)
    if (toArm)
    {
        // Send event to ARM
        #define DATA_SIZE 1024
        char cmd2[DATA_SIZE] = {0};
        sprintf(cmd2, "rpcclient2 \"syscfg set %s \'%s\'; syscfg commit\"", name, str_value);
        system(cmd2);
    }
#endif
   return retval;
}

// Invoke systemctl to get the running/stopped state of a service
int svcagt_get_service_state (const char *svc_name)
{
	int exit_code;
	bool running;
	char cmdbuf[128] = {0};
        /* Coverity Fix CID :62962 DC.STRING_BUFFER  */
	#if 0
	snprintf (cmdbuf,sizeof(cmdbuf), "%s is-active %s.service", svcagt_systemctl_cmd, svc_name);
	#else
	snprintf(cmdbuf,sizeof(cmdbuf), "pidof /usr/bin/dm");
	#endif
	exit_code = system (cmdbuf);
	if (exit_code == -1) {
		CcspTraceError(("Error invoking systemctl command, errno: %s\n", strerror(errno)));
		return -1;
	}
	running = (exit_code == 0);
	return running;
}

// Invoke systemctl to start or stop a service
int svcagt_set_service_state (const char *svc_name, bool state)
{
	int exit_code = 0;
	char cmdbuf[128] = {0};
	const char *start_stop_msg = NULL;
	const char *cmd_option = NULL;

	if (state) {
		start_stop_msg = "Starting";
		cmd_option = "start";
	} else {
		start_stop_msg = "Stopping";
		cmd_option = "stop";
	}

	MeshInfo(("%s %s\n", start_stop_msg, svc_name));
        /* Coverity Fix CID:58223 DC.STRING_BUFFER */
	#if 0
	snprintf (cmdbuf,sizeof(cmdbuf), "%s %s %s.service", 
		svcagt_systemctl_cmd, cmd_option, svc_name); 
	#else
	snprintf(cmdbuf,sizeof(cmdbuf), "/usr/plume/scripts/managers.init %s", cmd_option);
	#endif
	exit_code = system (cmdbuf);
	if (exit_code != 0)
		CcspTraceError(("Command %s failed with exit %d, errno %s\n",
			cmdbuf, exit_code, strerror(errno)));
	return exit_code;
}


#endif // _RDKB_MESH_UTILS_C_
