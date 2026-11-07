#!/system/bin/sh
setsid /data/local/tmp/tvagent </dev/null >/data/local/tmp/agent.log 2>&1 &
sleep 1
echo started > /data/local/tmp/agent_started.txt

