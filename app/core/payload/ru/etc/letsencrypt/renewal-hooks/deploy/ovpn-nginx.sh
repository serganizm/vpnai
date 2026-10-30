#!/bin/sh
set -e
/usr/sbin/nginx -t
/usr/bin/systemctl reload nginx
