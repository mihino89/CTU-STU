#! /usr/bin/bash

filename="$1"
declare -i i=0
cat "$filename" > tmp.txt;

#check if file exists and it's readable
if [[ ! -f "$filename" ]] && [[ ! -r "$filename" ]]; then
        >&2 echo "File "$filename" is not exist";
        exit 1;
fi

cat "$filename" | while read line; do
	testik="$(echo $line | grep -Ewo '\<bl[a-z]+|\<Bl[a-z]+|^bl$')";
	if [ ! -z "$testik" ]; then
		i+=1;
		echo $i > num_tmp.txt;
		echo "$testik" >> tmp_strings.txt;
	fi
done

cat tmp_strings.txt | while read line; do
	sed -i "s/$line/xxxx/g" tmp.txt;
done

num_lines="$( cat "$filename" | wc -l )";
echo "---" >> tmp.txt
echo "Out of a total of $num_lines rows, "$( cat num_tmp.txt )" were censored" >> tmp.txt;

cat tmp.txt
#cat tmp.txt > "$filename";

#rm -r tmp.txt;
rm -r num_tmp.txt;
rm -r tmp_strings.txt;
