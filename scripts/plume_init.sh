#!/bin/sh

while [ ! -f /tmp/meshagent_initialized ]
do
    /bin/sleep 5
done

start_plume() {

    son_admin="`rpcclient 192.168.254.253 'syscfg get son_admin_status' | tail -n 2 | head -n 1`"

    if [ "$son_admin" != "1" ]; then
        echo "Plume disabled"
        exit 1
    fi

    son_operation="`rpcclient 192.168.254.253 'syscfg get son_operational_status' | tail -n 2 | head -n 1`"

    if [ "$son_operation" != "1" ]; then
        echo "Plume disabled"
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
