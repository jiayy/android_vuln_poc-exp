add-symbol-file ./6pack.ko <ADDRESS> # Via cat /sys/module/6pack/sections/.text
target remote :1234
b decode_data
c
del 1 
p &sp->rx_count
p &sp->rx_count_cooked
watch *$1 if sp->rx_count_cooked >= 0x190
watch *$2 if sp->rx_count_cooked >= 0x190
c
define go
c
echo rx_count_cooked: 
p sp->rx_count_cooked
echo rx_count: 
p sp->rx_count
echo ---------- raw_buff ----------\n
x/gx &sp->raw_buf
echo ---------- cooked_buf ---------\n
x/10gx &sp->cooked_buf[400]
end

