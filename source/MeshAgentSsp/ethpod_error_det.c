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

#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <memory.h>
#include <unistd.h>

#include "ethpod_error_det.h"
#include "cosa_mesh_parodus.h"
#include "meshagent.h"
#include "cosa_meshagent_internal.h"
#include "cosa_apis_util.h"

#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>

#define POD_TIMEOUT_MS 60000
#define LS_READ_ETHLINKTIMEOUT_MS 2000

typedef enum _connstate {
    POD_DISCONNECTED_ST,
    POD_DETECTED_ST,
    POD_VLAN_CONNECTED_ST,
    POD_CONNECTED_ST
} PodConnState;

typedef struct _podstate {
    PodConnState state;
    char mac[MAX_MAC_ADDR_LEN];   //TODO: replace with fixed size string
    uint64_t timeout;
    struct _podstate *next;
} PodState;

//TODO: return some status instead of void
static bool getTime(uint64_t* time);
static void handlePodDC(PodState* pod);
static void handleDhcpAckPriv(PodState* pod);
static void handleDhcpAckVlan(PodState* pod);
static void handleDhcpAckBhaul(PodState* pod);

static PodState* pod_list = NULL;
static PodState* pod_list_tail = NULL;
static bool ignoreLinkEvent = false;

#ifdef ONEWIFI
extern COSA_DATAMODEL_MESHAGENT* g_pMeshAgent;
extern void  Mesh_sendCurrentSta();
extern bool  Mesh_isExtEthConnected();
extern bool xle_eth_up;
#endif

void setIgnoreLinkEvent(bool enable) {
    ignoreLinkEvent = enable;
}

bool meshAddPod(const char *pod_mac) {

    if(pod_mac == NULL) {
        MeshError("Trying to add a new pod with NULL pod_mac\n");
        return false;
    }

    MeshInfo("Adding new pod_mac: %s\n", pod_mac);
    PodState* new_pod = (PodState*) malloc(sizeof(PodState));
    if(new_pod == NULL) {
        MeshError("Failed to allocate memory for new PodState node\n");
        return false;
    }

    memset(new_pod, 0, sizeof(PodState));
    strncpy(new_pod->mac, pod_mac, sizeof(new_pod->mac));
    new_pod->mac[MAX_MAC_ADDR_LEN-1] = 0;
    new_pod->state = POD_DISCONNECTED_ST;
    new_pod->next = NULL;
    new_pod->timeout = 0;

    if(pod_list == NULL) {
        pod_list = new_pod;
        pod_list_tail = new_pod;
        return true;
    }

    pod_list_tail->next = new_pod;
    pod_list_tail = new_pod;
    return true;
}

bool meshRemovePods() {

    if(pod_list == NULL) {
        return true;
    }

    PodState* temp = pod_list;
    while(pod_list != NULL) {
        temp = pod_list->next;
        free(pod_list);
        pod_list = temp;
    }

    pod_list = NULL;
    pod_list_tail = NULL;
    return true;
}

bool meshHandleEvent(const char * pod_mac, EthPodEvent event) {

    PodState* pod = NULL;
    PodState* temp = NULL;


    for(temp = pod_list; temp != NULL; temp = temp->next) {
        if( strcmp(temp->mac, pod_mac) == 0) {
            pod = temp;
            break;
        }
    }

    if(pod == NULL) {
        MeshError("Pod not found in list, mac: %s\n", pod_mac);
        return false;
    }

    switch(event) {
        case DHCP_ACK_PRIV_EVENT:
            MeshInfo("Event DHCP_ACK_PRIV_EVENT recvd, moving to state POD_DETECTED_ST MAC: %s\n", pod->mac);
            handleDhcpAckPriv(pod);
            break;
        case DHCP_ACK_VLAN_EVENT:
            MeshInfo("Event DHCP_ACK_VLAN_EVENT recvd, moving to state POD_VLAN_CONNECTED_ST MAC: %s \n", pod->mac);
            handleDhcpAckVlan(pod);
            break;
        case DHCP_ACK_BHAUL_EVENT:
            MeshInfo("Event DHCP_ACK_BHAUL_EVENT recvd, moving to state POD_CONNECTED_ST MAC: %s \n", pod->mac);
            handleDhcpAckBhaul(pod);
            break;
        case POD_DC_EVENT:
            handlePodDC(pod);
            break;
        default:
            break;
    }

    return true;
}

void meshHandleTimeout() {
    PodState* pod = NULL;
    uint64_t currTime = 0;

    if(pod_list == NULL) {
        return;
    }

    if(getTime(&currTime) == false) {
        MeshError("Failed to fetch the current time.\n");
        return;
    }

    for(pod = pod_list; pod != NULL; pod = pod->next) {
        if(currTime >= pod->timeout && pod->state != POD_DISCONNECTED_ST && pod->state != POD_CONNECTED_ST) {
            MeshInfo("Pod has timed out! mac: %s\n", pod->mac);
            notifyEvent(ERROR, EB_GENERIC_ISSUE, pod->mac);
            //TODO: Send xFi notification
            pod->state = POD_DISCONNECTED_ST;
            pod->timeout = 0;
        }
    }
}

void handlePodDC(PodState* pod) {
    pod->state = POD_DISCONNECTED_ST;
    pod->timeout = 0;
}

void handleDhcpAckPriv(PodState* pod) {
    uint64_t currTime;
    if(getTime(&currTime) == false) {
        MeshError("Failed to get the current time!\n");
        pod->state = POD_DISCONNECTED_ST;
        pod->timeout = 0;
        return;
    }
    pod->state = POD_DETECTED_ST;
    pod->timeout = currTime + POD_TIMEOUT_MS;
}

void handleDhcpAckVlan(PodState* pod) {
    uint64_t currTime;
    if(getTime(&currTime) == false) {
        MeshError("Failed to get the current time!\n");
        pod->state = POD_DISCONNECTED_ST;
        pod->timeout = 0;
        return;
    }

    pod->state = POD_VLAN_CONNECTED_ST;
    pod->timeout = currTime + POD_TIMEOUT_MS;
}

void handleDhcpAckBhaul(PodState* pod) {
    pod->state = POD_CONNECTED_ST;
    pod->timeout = 0;
}

/** Returns current timestamp in milliseconds **/
bool getTime(uint64_t* time) {
    struct timespec tms = {0};
    if(clock_gettime(CLOCK_REALTIME, &tms)) {
        MeshError("Failed to fetch appropriate time\n");
        return false;
    }

    *time = tms.tv_sec * 1000;
    *time += tms.tv_nsec/1000000;
    return true;
}
#ifdef ONEWIFI
static void parseRtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;
        }
        rta = RTA_NEXT(rta,len);
    }
}

static ssize_t ethlinkRead( int fd, struct msghdr *msg,  int timeout)
{
    int ret = 0;
    ssize_t len = 0;
    fd_set read_flags;
    struct timeval tv = {0};

    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    FD_ZERO(&read_flags);
    FD_SET(fd, &read_flags);

    ret = select(fd + 1, &read_flags, NULL, NULL, &tv);
    if(ret == 0){
        return 0;
    }
    else if(ret < 0){
        MeshError("%s Select socket::error=%s|errno=%d\n", __func__, strerror(errno), errno);
        return -2;
    }

    if (FD_ISSET(fd, &read_flags))
    {
        FD_CLR(fd, &read_flags);
        len = recvmsg(fd, msg, MSG_DONTWAIT);
    }
    return len;
}

bool isLinkReadPauseExpired()
{
   static int ignoreLinkEventThreshold = 5;
   bool ret = false;

   if(ignoreLinkEvent && ignoreLinkEventThreshold > 0)
   {
      ignoreLinkEventThreshold--;
      usleep(5000000);
   }

   if(ignoreLinkEventThreshold == 0)
   {
      ret = true;
      ignoreLinkEvent = false;
      ignoreLinkEventThreshold = 5;
      MeshInfo("%s Link pause threshold reached, continue link monitor\n", __func__);
   }
   return ret;
}

void *extEthLinkMonitor()
{
    struct nlmsghdr *h;
    struct sockaddr_nl  local;
    char buf[8192];
    struct iovec iov;
    char *ifName = NULL;
    static bool prevStatus = false;
    int fd;
    ssize_t status;

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (fd < 0) {
        MeshError("%s Failed to create netlink socket: %s\n", __func__, (char*)strerror(errno));
        goto clean_up;
    }

    MeshInfo("Starting extEthLinkMonitor thread....\n");

    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    memset(&local, 0, sizeof(local));

    local.nl_family = AF_NETLINK;
    local.nl_groups =   RTMGRP_LINK;
    local.nl_pid = getpid();

    struct msghdr msg;
    {
        msg.msg_name = &local;
        msg.msg_namelen = sizeof(local);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
    }

    if (bind(fd, (struct sockaddr*)&local, sizeof(local)) < 0)
    {
        MeshInfo("Failed to bind netlink socket: %s\n", (char*)strerror(errno));
        goto clean_up;
    }

    while (1) {

        if (!g_pMeshAgent->ExtEthPortEnable)
            goto clean_up;

        if(isLinkReadPauseExpired() && prevStatus != Mesh_isExtEthConnected())
        {
             MeshInfo("Link detect pause timer expired, send latest status\n");
             prevStatus = Mesh_isExtEthConnected();
             Mesh_sendCurrentSta();
        }

        status = ethlinkRead(fd, &msg, LS_READ_ETHLINKTIMEOUT_MS);

        if(status == 0)
            continue;

        if (status < 0) {
            if (errno == EINTR || errno == EAGAIN)
            {
                usleep(250000);
                continue;
            }

            MeshInfo("Failed to read netlink: %s", (char*)strerror(errno));
            continue;
        }

        if (msg.msg_namelen != sizeof(local))
        {
            MeshInfo("Invalid length of the sender address struct\n");
            continue;
        }

        for (h = (struct nlmsghdr*)buf; status >= (ssize_t)sizeof(*h); )
        {
            int len = h->nlmsg_len;
            int l = len - sizeof(*h);

            if ((l < 0) || (len > status)) {
                MeshError("%s Invalid message length: %i\n", __func__, len);
                continue;
            }

            if (!((h->nlmsg_type == RTM_NEWROUTE) || (h->nlmsg_type == RTM_DELROUTE)))
            {
                struct ifinfomsg *ifi;
                struct rtattr *tb[IFLA_MAX + 1];

                ifi = (struct ifinfomsg*) NLMSG_DATA(h);

                parseRtattr(tb, IFLA_MAX, IFLA_RTA(ifi), h->nlmsg_len);

                if (tb[IFLA_IFNAME]) {
                    ifName = (char*)RTA_DATA(tb[IFLA_IFNAME]);
                }

                if((ifName !=NULL) && (!strcmp(ifName,"eth0")) && (!ignoreLinkEvent))
                {
                    if (ifi->ifi_flags & IFF_RUNNING) {
                        MeshInfo("EBH_XLE eth0 is running\n");
                        if(!prevStatus) {
                        prevStatus=true;
                        Mesh_sendCurrentSta();
                        }
                        xle_eth_up =true;
                    } else {
                        xle_eth_up = false;
                        if(prevStatus) {
                        prevStatus=false;
                        Mesh_sendCurrentSta();
                        MeshInfo("EBH_XLE eth0 is not running, switching to wl\n");
                        }
                    }
                }
                struct ifaddrmsg *ifa;
                struct rtattr *tba[IFA_MAX+1];

                ifa = (struct ifaddrmsg*)NLMSG_DATA(h);

                parseRtattr(tba, IFA_MAX, IFA_RTA(ifa), h->nlmsg_len);
            }

            status -= NLMSG_ALIGN(len);

            h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
        }

    }
clean_up:

    close(fd);

    return 0;
}
#endif
