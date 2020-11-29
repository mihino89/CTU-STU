#! /usr/bin/bash

echo 'Symbol,Name,Sector,Market Cap $K,Last' > table.csv;

tail -n +2 "$FILE" | sed 's/,//g' | awk '
{
	if (NR%5==0){
		a=a $0" ";print a; a=""
	} else a=a $0","
}' >> tmp.csv;

awk '{print $1,$2,$3,$4,$5}' tmp.csv >> table.csv;
rm -r tmp.csv;

cat table.csv
