#!/bin/bash

day=$(date | awk '{print $3;}' | tr -d ','); 
hours=$(date | cut -d' ' -f5 | cut -d':' -f1);  
minutes=$( date | cut -d' ' -f5 | cut -d':' -f2);
sum=$((day+hours+minutes)); 

echo $sum > $UID.txt; echo '(c) mihalma5' >> $UID.txt
