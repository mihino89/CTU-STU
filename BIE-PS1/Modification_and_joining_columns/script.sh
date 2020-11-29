#! /usr/bin/bash

cat "$FILE" | tr -d [:digit:] | tr '[:upper:]' '[:lower:]' | sort | pr -t -3 -s | nl > tmp.txt; cat tmp.txt  > "$FILE"; rm tmp.txt
