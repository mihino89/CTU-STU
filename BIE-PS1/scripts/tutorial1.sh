#! /usr/bin/bash

if [ $# -ne 2 ] ; then
	echo "Usage: script num1 num2" >&2
	exit 1
fi

if [ $1 -ge $2 ]; then
	echo $1
else
	echo $2
fi
