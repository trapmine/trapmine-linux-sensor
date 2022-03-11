#!/bin/bash

if [ "$EUID" -ne 0 ] 
	then echo "make install needs superuser priviliges"
	exit 1
fi

mkdir -p /opt/trapmine/agent
mkdir -p /opt/trapmine/db
mkdir -p /opt/trapmine/dumps

cp ./build/sensor-core /opt/trapmine/agent
