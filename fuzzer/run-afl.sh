#!/system/bin/sh

if [ -f "/data/local/tmp/out/fuzzer_stats" ]
then
    cat /data/local/tmp/out/fuzzer_stats
    rm /data/local/tmp/out/fuzzer_stats
fi
AFL_NO_ARITH=1 AFL_NO_UI=1 AFL_FAST_CAL=1 AFL_NO_FORKSRV=1 AFL_SKIP_CPUFREQ=1 /data/local/tmp/fuzzer -i- -o /data/local/tmp/out -t 500000+ /data/local/tmp/executor @@ > /dev/null 2> /dev/null &

exit 0
