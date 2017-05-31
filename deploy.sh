#!/bin/bash

make
echo "copying bin/tracer onto 172.21.7.12"
scp bin/tracer root@172.21.7.12:
echo "copyint bin/tracer onto 222.186.19.243"
scp bin/tracer root@222.186.19.243:
echo "copyint bin/tracer onto 118.123.116.24"
scp bin/tracer root@118.123.116.24:
