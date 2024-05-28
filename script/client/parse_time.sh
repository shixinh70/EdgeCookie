#!/bin/bash

# 设置计数器和时间数组
count=100
time_namelookup_array=()
time_connect_array=()
time_appconnect_array=()
time_pretransfer_array=()
time_redirect_array=()
time_starttransfer_array=()
time_total_array=()

# 循环执行curl命令并记录时间
for ((i=1; i<=$count; i++))
do
    result=$(curl -w "@curl-format.txt" -o /dev/null -s "10.19.0.3")
    
    # 从curl的输出中提取各个时间指标
    time_namelookup=$(echo "$result" | grep "time_namelookup" | awk '{print $2}' | sed 's/s//')
    time_connect=$(echo "$result" | grep "time_connect" | awk '{print $2}' | sed 's/s//')
    time_appconnect=$(echo "$result" | grep "time_appconnect" | awk '{print $2}' | sed 's/s//')
    time_pretransfer=$(echo "$result" | grep "time_pretransfer" | awk '{print $2}' | sed 's/s//')
    time_redirect=$(echo "$result" | grep "time_redirect" | awk '{print $2}' | sed 's/s//')
    time_starttransfer=$(echo "$result" | grep "time_starttransfer" | awk '{print $2}' | sed 's/s//')
    time_total=$(echo "$result" | grep "time_total" | awk '{print $2}' | sed 's/s//')
    
    # 将时间添加到对应的数组中
    time_namelookup_array+=("$time_namelookup")
    time_connect_array+=("$time_connect")
    time_appconnect_array+=("$time_appconnect")
    time_pretransfer_array+=("$time_pretransfer")
    time_redirect_array+=("$time_redirect")
    time_starttransfer_array+=("$time_starttransfer")
    time_total_array+=("$time_total")
    
    echo "Iteration $i:"
    echo "time_namelookup: $time_namelookup seconds"
    echo "time_connect: $time_connect seconds"
    echo "time_appconnect: $time_appconnect seconds"
    echo "time_pretransfer: $time_pretransfer seconds"
    echo "time_redirect: $time_redirect seconds"
    echo "time_starttransfer: $time_starttransfer seconds"
    echo "time_total: $time_total seconds"
    echo "-----------------------------------"
done

# 计算每个时间指标的平均值
average_time_namelookup=$(echo "${time_namelookup_array[@]}" | tr ' ' '\n' | awk '{sum += $1} END {print sum / NR}')
average_time_connect=$(echo "${time_connect_array[@]}" | tr ' ' '\n' | awk '{sum += $1} END {print sum / NR}')
average_time_appconnect=$(echo "${time_appconnect_array[@]}" | tr ' ' '\n' | awk '{sum += $1} END {print sum / NR}')
average_time_pretransfer=$(echo "${time_pretransfer_array[@]}" | tr ' ' '\n' | awk '{sum += $1} END {print sum / NR}')
average_time_redirect=$(echo "${time_redirect_array[@]}" | tr ' ' '\n' | awk '{sum += $1} END {print sum / NR}')
average_time_starttransfer=$(echo "${time_starttransfer_array[@]}" | tr ' ' '\n' | awk '{sum += $1} END {print sum / NR}')
average_time_total=$(echo "${time_total_array[@]}" | tr ' ' '\n' | awk '{sum += $1} END {print sum / NR}')

# 输出每个时间指标的平均值
echo "Average time_namelookup: $average_time_namelookup seconds"
echo "Average time_connect: $average_time_connect seconds"
echo "Average time_appconnect: $average_time_appconnect seconds"
echo "Average time_pretransfer: $average_time_pretransfer seconds"
echo "Average time_redirect: $average_time_redirect seconds"
echo "Average time_starttransfer: $average_time_starttransfer seconds"
echo "Average time_total: $average_time_total seconds"
