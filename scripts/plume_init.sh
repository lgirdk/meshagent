#!/bin/sh

. /etc/device.properties

if [ "$BOX_TYPE" = "MV1" ] && [ ! -f /tmp/wifi_first_init ]
then
    exit 1
fi

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
        exit 1
    fi

    if [ "$BOX_TYPE" = "MV1" ]; then
        br_mode="$(rpcclient2 'syscfg get bridge_mode' | tail -n 2 | head -n 1)"
    else
        br_mode="$(syscfg get bridge_mode)"
    fi

    if [ "$br_mode" != "0" ]; then
        echo "In Bridge mode, opensync disabled"
        exit 1
    fi

    echo "Starting Plume manager"

    if [ "$BOX_TYPE" = "MV1" ]; then
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
