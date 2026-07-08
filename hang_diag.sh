#!/bin/bash
cd /workspace
pkill -9 -f testhost 2>/dev/null
sleep 1

timeout 30 dotnet test DynamicHook.Tests/DynamicHook.Tests.csproj -c Debug -f net8.0 --no-build > /tmp/so_diag.txt 2>/tmp/se_diag.txt &
TPID=$!
echo "Started parent $TPID" > /tmp/diag_out.txt

for sec in $(seq 1 25); do
  sleep 1
  if ! kill -0 $TPID 2>/dev/null; then
    echo "sec=$sec: parent finished" >> /tmp/diag_out.txt
    grep "Passed!" /tmp/so_diag.txt >> /tmp/diag_out.txt 2>/dev/null && echo "RESULT=PASS" >> /tmp/diag_out.txt || echo "RESULT=FAIL" >> /tmp/diag_out.txt
    break
  fi
  THP=$(ps aux | grep "testhost.dll" | grep -v grep | awk '{print $2}' | head -1)
  if [ -n "$THP" ]; then
    CPU=$(ps -p $THP -o pcpu= 2>/dev/null | tr -d ' ')
    STATE=$(cat /proc/$THP/stat 2>/dev/null | awk '{print $3}')
    UTIME=$(cat /proc/$THP/stat 2>/dev/null | awk '{print $14}')
    echo "sec=$sec testhost=$THP cpu=$CPU state=$STATE utime=$UTIME" >> /tmp/diag_out.txt
    if [ "$sec" -eq 12 ]; then
      echo "=== DETAILED at sec=12 ===" >> /tmp/diag_out.txt
      echo "threads:" >> /tmp/diag_out.txt
      for t in $(ls /proc/$THP/task 2>/dev/null); do
        TSTAT=$(cat /proc/$THP/task/$t/stat 2>/dev/null)
        TSTATE=$(echo "$TSTAT" | awk '{print $3}')
        TUTIME=$(echo "$TSTAT" | awk '{print $14}')
        TWCHAN=$(cat /proc/$THP/task/$t/wchan 2>/dev/null)
        echo "  tid=$t state=$TSTATE utime=$TUTIME wchan=$TWCHAN" >> /tmp/diag_out.txt
      done
    fi
  fi
done

kill -9 $TPID 2>/dev/null
pkill -9 -f testhost 2>/dev/null
echo "DONE" >> /tmp/diag_out.txt
