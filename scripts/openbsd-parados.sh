#!/bin/ksh

daemon="/usr/local/bin/parados"
rc_bg=YES

. /etc/rc.d/rc.subr

rc_cmd $1

