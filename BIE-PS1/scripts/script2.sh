#! /usr/bin/bash

echo "---------------------"
date
echo "  - Users:	$( finger | tail -n+2 | wc -l )"
echo "  - Processes:	$( ps -e | tail -n+2 | wc -l)" 
echo "  - Threads: 	$( ps -eL | tail -n+2 | wc -l)"

