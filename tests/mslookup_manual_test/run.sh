#!/bin/sh
srcdir="${1:-.}"
builddir="${2:-.}"

cd "$builddir"

osmo-hlr -c "$srcdir/osmo-hlr-1.cfg" -l hlr1.db &
sleep 1
osmo-hlr -c "$srcdir/osmo-hlr-2.cfg" -l hlr2.db &

sleep 1
osmo_interact_vty.py -H 127.0.0.1 -p 4258 -c 'enable; subscriber imsi 111111 create; subscriber imsi 111111 update msisdn 1'
osmo_interact_vty.py -H 127.0.0.2 -p 4258 -c 'enable; subscriber imsi 222222 create; subscriber imsi 222222 update msisdn 2'
sleep 1

./fake_msc &

echo enter to exit
read enter_to_exit
kill %1 %2 %3
killall osmo-hlr
killall fake_msc
