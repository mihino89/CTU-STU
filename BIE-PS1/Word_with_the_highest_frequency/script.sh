#! /usr/bin/bash

cat "$DIR"/*.txt | tr -c '[[:alpha:]]' '\n' | awk 'length == 7' | sort | uniq -c | sort -nr | awk '{print $2}' | head -n 1
