#!/bin/sh

if [ ! -f /tmp/wifi_first_init ]; then
    exit 1
fi

start_plume() {

    while [ ! -f /tmp/meshagent_initialized ]
    do
       /bin/sleep 5
    done

    while ! son_admin=$(cat /tmp/.syscfg_son_admin_status 2>/dev/null) || [ -z "$son_admin" ]; do
        echo "Error getting son_admin_status, retrying"
        sleep 1
    done

    if [ "$son_admin" != "1" ]; then
        echo "Plume son_admin_status disabled"
        exit 1
    fi

    while ! son_operation=$(cat /tmp/.syscfg_son_operational_status 2>/dev/null) || [ -z "$son_operation" ]; do
        echo "Error getting son_operational_status, retrying"
        sleep 1
    done

    if [ "$son_operation" != "1" ]; then
        echo "Plume son_operational_status disabled"
        exit 1
    fi

    br_mode="`rpcclient2 'syscfg get bridge_mode' | tail -n 2 | head -n 1`"
    if [ "$br_mode" != "0" ]; then
        echo "In Bridge mode, opensync disabled"
        exit 1
    fi

    echo "Starting Plume manager"

    /usr/plume/scripts/managers.init start
}

stop_plume() {
    /usr/plume/scripts/managers.init stop
    echo -e "group_remove\n" | plume_netlink
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
