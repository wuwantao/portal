#!/bin/ash

sqlite3 /data/portal.db 'delete  from  portal'
sendarp_pid=`cat /tmp/sendarp.pid`
echo $sendarp_pid
kill -16 $sendarp_pid
