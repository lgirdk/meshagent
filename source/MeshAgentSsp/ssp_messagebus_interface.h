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

/**
 * @file ssp_messagebus_interface.h
 *
 * @description This header defines the Message Bus initialization and component path registration methods.
 */

/**
 * @brief SSP messagebus specific defines.
 */
#ifndef  _SSP_MESSAGEBUS_INTERFACE_
#define  _SSP_MESSAGEBUS_INTERFACE_

ANSC_STATUS
ssp_Mbi_MessageBusEngage
    (
        char * component_id,
        char * config_file,
        char * path
    );

int
ssp_Mbi_Initialize
    (
        void * user_data
    );

int
ssp_Mbi_Finalize
    (
        void * user_data
    );

int
ssp_Mbi_Buscheck
    (
        void * user_data
    );

int
ssp_Mbi_FreeResources
    (
        int priority,
        void * user_data
    );

#endif
