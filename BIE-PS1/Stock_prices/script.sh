#! /usr/bin/bash

filename="$1"
sectorname="$2"

del=","
concat_str=$del$sectorname
lines="$(grep "$concat_str" "$filename")"

if [[ ! $lines =~ [^[:space:]] ]] ; then
        >&2 echo "Wrong sector"
        >&2 echo "Usage: /gen.sh file sector"
        exit 1
fi

num_lines="$(echo "$lines" | wc -l)"

if [ $num_lines > 0 ]; then
        echo "Shares from the sector \""$sectorname"\""
        pom_num="$( echo "$sectorname" | wc -c )"
        calc=$(( 24 + pom_num ))
        for i in $(seq 1 $calc); do printf "-"; done
        printf "\n"
        echo "$lines"
        for i in $(seq 1 $calc); do printf "-"; done
        printf "\n"
        all_nums="$(echo "$lines" | awk -F',' '{ print $5 }')"
        avrg="$(echo "$all_nums" $num_lines | awk '{s+=$1}END{printf "%.2f", s/$2}')"
        min="$(echo "$all_nums" | sort -n | head -n 1)"
        max="$(echo "$all_nums" | sort -n | tail -1)"
        printf "minimum last price = $min\taverage last price = $avrg\tmaximum last price= $max"
fi
