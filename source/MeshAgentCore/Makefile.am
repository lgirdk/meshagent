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
AM_LDFLAGS = -lccsp_common -lwebconfig_framework

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

bin_PROGRAMS = meshAgent
meshAgent_CPPFLAGS = -I$(top_srcdir)/source/MeshAgentCore -I$(top_srcdir)/source/MeshAgentSsp -I$(top_srcdir)/source/include $(CPPFLAGS)

meshAgent_SOURCES = meshagent.c
meshAgent_LDADD = ${top_builddir}/source/MeshAgentSsp/libMeshAgentSsp.la
meshAgent_CFLAGS = $(SYSTEMD_CFLAGS) 
meshAgent_CFLAGS += "-DFEATURE_SUPPORT_RDKLOG"
meshAgent_LDFLAGS = -lccsp_common -ldl -rdynamic -lwebconfig_framework $(SYSTEMD_LDFLAGS) -llog4c
