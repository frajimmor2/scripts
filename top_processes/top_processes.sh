ps -eo comm,%cpu --sort=-%cpu | tail -n +2 | head -n 5 | while read name cpu; do
    printf "%s - %.1f%%\n" "$name" "$cpu"
done
