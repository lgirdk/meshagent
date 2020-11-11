#!/bin/sh

rpc_error_grep() {
        grep -q -e "\*\*\* RPC CONNECTED \*\*\*" -e "RPC CONNECTION FAILED \!\!\!\!\!"
}

if [ ! -f /tmp/wifi_first_init ]; then
    exit 1
fi

while [ ! -f /tmp/meshagent_initialized ]
do
    /bin/sleep 5
done

start_plume() {

    son_admin="`rpcclient2 'syscfg get son_admin_status' | tail -n 2 | head -n 1`"
    while rpc_error_grep <<< $son_admin; do
        echo "Error getting son_admin_status, retrying"
        sleep 1
        son_admin="`rpcclient2 'syscfg get son_admin_status' | tail -n 2 | head -n 1`"
    done

    if [ "$son_admin" != "1" ]; then
        echo "Plume son_admin_status disabled"
        exit 1
    fi

    son_operation="`rpcclient2 'syscfg get son_operational_status' | tail -n 2 | head -n 1`"
    while rpc_error_grep <<< $son_operation; do
        echo "Error getting son_operational_status, retrying"
        sleep 1
        son_operation="`rpcclient2 'syscfg get son_operational_status' | tail -n 2 | head -n 1`"
    done

    if [ "$son_operation" != "1" ]; then
        echo "Plume son_operational_status disabled"
        exit 1
    fi

    echo "Starting Plume manager"

    /usr/plume/scripts/managers.init start
}

stop_plume() {
    /usr/plume/scripts/managers.init stop
}

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
