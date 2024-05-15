#!/bin/bash

# 檢查是否提供了正確的參數
if [ $# -ne 1 ]; then
    echo "使用方法: $0 <N>"
    exit 1
fi

# 設定計數器和總時間
count=0
total_time=0

# 迭代N秒
for (( i=0; i<$1; i++ )); do
    # 使用curl計算時間
    result=$(curl -so /dev/null -w '%{time_total}\n' 10.19.0.3)

    # 將時間加到總時間
    total_time=$(echo "$total_time + $result" | bc)

    # 增加計數器
    count=$((count+1))

    # 暫停一秒
    sleep 1
done

# 計算平均時間
average_time=$(echo "scale=7; $total_time / $count" | bc)

# 輸出結果
echo "總時間: $total_time 秒"
echo "平均時間: $average_time 秒"
