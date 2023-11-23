#!/bin/bash

PROG='iredapd'
BINPATH='/opt/iredapd/iredapd.py'
#DELCACHE='/opt/iredapd/delete_cache.py'
PIDFILE='/var/run/iredapd.pid'
CLEANDB='/opt/iredapd/tools/cleanup_db.py'

## Config log local0 (level 16)
cp /home/51-ired-rsyslog.conf /etc/rsyslog.d/51-ired-rsyslog.conf
# systemctl restart rsyslog

if [ "$PROCESS" == "main" ];then
#  echo "deleting cache"
  rm -f ${PIDFILE} >/dev/null 2>&1
#  /usr/bin/python ${DELCACHE}
  echo "starting ${PROG}"
  /usr/bin/python3 ${BINPATH}
  tail -f /dev/null
fi

if [ "$PROCESS" == "clean_throttle_db_daily" ];then
  echo "Cleaning throttle_db daily"
  /usr/bin/python3 ${CLEANDB} >/dev/null
fi

