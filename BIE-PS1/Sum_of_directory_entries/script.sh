VAR=$(ls -la "$DIR" | head -1 | cut -d" " -f2); ans=$(( VAR - 1 )); echo "In the directory $DIR, there are $ans entries"; echo "In the directory $DIR, there are $ans entries" > "$FILE"
