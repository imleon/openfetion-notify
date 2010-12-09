#!/bin/sh
####以1.8为库##
rm -rf myofetion.o myofetion
gcc -g -c -o myofetion.o myofetion.c -I/usr/include/libxml2 -lxml2 -I./include/
gcc -g -o myofetion myofetion.o libofetion.a -lcurl -lpthread -lxml2 -lsqlite3
