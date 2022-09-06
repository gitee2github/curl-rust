# #!/bin/bash

# # TODO 需要填充url列表，需要修改两个循环中请求curl和curl-rust的方式，如果感觉写的不好，可以完全重写一份

# # urls to be requested in the performance test
# # TODO  fill it with url
# url_lists=(
#     "www.baidu.com"
#     "ustc.edu.cn"
# )

# # time spent when requesting each url using curl
# curl_time=()

# # time spent when requesting each url using curl-rust
# curl_rust_time=()

# length=${#url_lists[@]}

# # times we request an url
# counts=10

# echo "-------------Performance Test-------------"

# echo "start testing curl..."

# index=0

# for list in ${url_lists[@]}
# do
#     echo "using curl to request ${list}..."
#     total=0
#     for ((j=0; j<${counts}; j++))
#     do
#         # invoke curl to request url and get the time it spent
#         time=`
# curl -w @- -o /dev/null -s "${list}" << 'EOF'
# %{time_total}\n 
# EOF
#               `
#         total=`echo "scale=5; ${total} + ${time}" | bc`
#     done
#     # calculate the average time it spent
#     average=`echo "scale=5; ${total} / ${counts}" | bc`
#     curl_time[${index}]=${average}
#     index=`expr ${index} + 1`
# done

# echo ${curl_time[@]}

# echo "start testing curl-rust..."

# index=0

# for list in ${url_lists[@]}
# do
#     echo "using curl-rust to request ${list}"
#     total=0
#     for ((j=0; j<${counts}; j++))
#     do
#         # invoke curl-rust to request url and get the time it spent
#         time=`
# curl -w @- -o /dev/null -s "${list}" << 'EOF'
# %{time_total}\n 
# EOF
#               `
#         total=`echo "scale=5; ${total} + ${time}" | bc`
#     done
#     # calculate the average time it spent
#     average=`echo "scale=5; ${total} / ${counts}" | bc`
#     curl_rust_time[${index}]=${average}
#     index=`expr ${index} + 1`
# done

# echo "calculating the performance gap of curl and curl-rust"

# for ((i=0; i<${length}; i++))
# do
#     gap=`echo "scale=5; ${curl_rust_time[i]} - ${curl_time[i]}" | bc`
#     gap=`echo "scale=5; ${gap} / ${curl_time[i]} * 100" | bc`
#     # write the result into file
#     echo "testcase${i}: time of curl spent: ${curl_time[i]}; time of curl-rust spent: ${curl_rust_time[i]};the rate of performance gap: ${gap}%" >> res.txt
# done

# echo "the result has been written into `pwd`/res.txt"
