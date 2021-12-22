##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libMeshAgentSsp.la

libMeshAgentSsp_la_CPPFLAGS = -I$(top_srcdir)/source/MeshAgentCore -I$(top_srcdir)/source/MeshAgentSsp -I$(top_srcdir)/source/include -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/ovsagent
libMeshAgentSsp_la_SOURCES = ssp_messagebus_interface.c ssp_main.c ssp_action.c plugin_main.c cosa_meshagent_internal.c cosa_meshagent_dml.c cosa_apis_util.c cosa_mesh_apis.c mesh_client_table.c cosa_webconfig_api.c helpers.c cosa_mesh_parodus.c ethpod_error_det.c
libMeshAgentSsp_la_LDFLAGS = -lccsp_common -ldl -rdynamic -lutapi -lutctx -lulog -lwebconfig_framework -llibparodus -lmsgpackc -ltrower-base64 -lprint_uptime -lsecure_wrapper -lz -lpthread -lrt  $(SYSTEMD_LDFLAGS)
