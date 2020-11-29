#! /usr/bin/bash

if [ -r $1 ] ; then
	echo "File $1 was $(wc -l < $1) lines."

else 
	echo "File $1 is not readable."
fi
