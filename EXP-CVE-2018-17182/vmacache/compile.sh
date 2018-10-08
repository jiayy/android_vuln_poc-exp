#!/bin/sh
gcc -o puppet puppet.c -nostdlib -O1
gcc -o puppeteer puppeteer.c -O1
gcc -o suidhelper suidhelper.c -O1
