#!/bin/sh

. /etc/device.properties

if [ "$BOX_TYPE" = "MV1" ] && [ ! -f /tmp/wifi_first_init ]
then
    exit 1
fi

#This is as part of ECO-2838(Only part 1 is implemented, part is done later, when the solution is added as a feature for all pltforms).
#part 1: Select channel 44 on device reboot when plume is enabled and reset when plume is disabled.
#part 2: Select the 2.4GHz channel that was selected by plume earlier. TODO

CHANNEL_SET_DONE=/tmp/channel_set_done
set_channel()
{
    if [ "$MODEL_NUM" = "TG2492" ]
    then
        if [ "$(cfg -v AP_PRIMARY_CH_2)" = "44" ]
        then
            cfg -a AP_PRIMARY_CH_2=0
        fi
        cfg -a AP_PRIMARY_CH=44
    else
        cfg -a AP_PRIMARY_CH_2=44
    fi

    cfg -c
}

reset_channel()
{
    if [ "$MODEL_NUM" = "TG2492" ]
    then
        cfg -a AP_PRIMARY_CH=0
    else
        cfg -a AP_PRIMARY_CH_2=0
    fi

    cfg -c
}

start_plume() {

    while [ ! -f /tmp/meshagent_initialized ]
    do
       /bin/sleep 5
    done

    if [ "$BOX_TYPE" = "MV1" ]; then
        while ! son_admin=$(cat /tmp/.syscfg_son_admin_status 2>/dev/null) || [ -z "$son_admin" ]; do
            echo "Error getting son_admin_status, retrying"
            sleep 1
        done
    else
        son_admin="$(syscfg get son_admin_status)"
    fi

    if [ "$son_admin" != "1" ]; then
        echo "Plume son_admin_status disabled"
        if [ -f "$CHANNEL_SET_DONE" ]; then
            reset_channel
            rm "$CHANNEL_SET_DONE"
        fi
        exit 1
    fi

    if [ "$BOX_TYPE" = "MV1" ]; then
        while ! son_operation=$(cat /tmp/.syscfg_son_operational_status 2>/dev/null) || [ -z "$son_operation" ]; do
            echo "Error getting son_operational_status, retrying"
            sleep 1
        done
    else
        son_operation="$(syscfg get son_operational_status)"
    fi

    if [ "$son_operation" != "1" ]; then
        echo "Plume son_operational_status disabled"
        if [ -f "$CHANNEL_SET_DONE" ]; then
            reset_channel
            rm "$CHANNEL_SET_DONE"
        fi
        exit 1
    fi

    if [ "$BOX_TYPE" = "MV1" ]; then
        br_mode="$(rpcclient2 'syscfg get bridge_mode' | tail -n 2 | head -n 1)"
    else
        br_mode="$(syscfg get bridge_mode)"
    fi

    if [ "$br_mode" != "0" ]; then
        echo "In Bridge mode, opensync disabled"
        if [ "$BOX_TYPE" = "MV1" ]; then
              ifconfig eth0.200 > /dev/null 2>&1
              if [ $? = "0" ]; then
                   kill SIGUSR2 $(cat /var/run/udhcpc-eth0.200.pid)
                   rm /var/run/udhcpc-eth0.200.pid
                   ip link del eth0.200
              fi
        fi
        exit 1
    fi

    echo "Starting Plume manager"

    if [ "$BOX_TYPE" = "MV1" ]; then
        if [ ! -f "$CHANNEL_SET_DONE" ]; then
            set_channel
            touch "$CHANNEL_SET_DONE"
        fi
        /usr/plume/scripts/managers.init start
    else
       /usr/bin/sysevent set mesh_enable "RDK|true"
       syscfg set mesh_ovs_enable true
       syscfg commit
    fi
}

stop_plume() {

    if [ "$BOX_TYPE" = "MV1" ]; then
        /usr/plume/scripts/managers.init stop
        echo -e "group_remove\n" | plume_netlink
    else
        /usr/bin/sysevent set mesh_enable "RDK|false"
        syscfg set mesh_ovs_enable false
        syscfg commit
    fi
}

fd=205
lockFile="/var/lock/$(basename $0)"
eval exec "$fd"'>"$lockFile"'

flock "$fd"
(
eval exec "$fd"'>&-'
case $1 in
    start)
        start_plume
        ;;
    stop)
        stop_plume
        ;;
    restart)
        stop_plume
        start_plume
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        ;;
esac
)
