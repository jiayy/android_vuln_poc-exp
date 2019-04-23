#define TEXT_ADDR           0x00000000000a5620
#define mprotect_ADDR       0x00000000000a2f10
#define madvise_ADDR        0x00000000000a3ca0
#define malloc_ADDR         0x00000000000a49e0
#define open_ADDR           0x00000000000a55b0
#define close_ADDR          0x00000000000a32e0
#define read_ADDR           0x00000000000a43f0
#define write_ADDR          0x00000000000a4ea0
#define dup2_ADDR           0x00000000000a3c00
#define pipe_ADDR           0x00000000000a47c0
#define select_ADDR         0x00000000000a2ed0
#define fork_ADDR           0x00000000000a4d40
#define execv_ADDR          0x00000000000a4ad0
#define system_ADDR         0x00000000000a5570
#define pthread_create_ADDR 0x00000000000a4200
#define qemu_set_irq_ADDR   0x0000000000277347

#define property_get_alias_ADDR          0x0000000000388f70
#define property_get_enum_ADDR           0x0000000000388746
#define property_get_tm_ADDR             0x000000000038898c
#define property_get_uint32_ptr_ADDR     0x0000000000388d72
#define property_get_uint8_ptr_ADDR      0x0000000000388cab
#define property_get_bool_ADDR           0x0000000000388511
#define property_get_str_ADDR            0x00000000003882bd
#define property_get_uint8_ptr_ADDR      0x0000000000388cab
#define property_get_uint16_ptr_ADDR     0x0000000000388d0e
#define property_get_uint32_ptr_ADDR     0x0000000000388d72
#define property_get_uint64_ptr_ADDR     0x0000000000388dd4
#define object_get_link_property_ADDR    0x0000000000387836
#define object_get_child_property_ADDR   0x0000000000387612
#define memory_region_get_size_ADDR      0x00000000000f6e1f
#define memory_region_get_addr_ADDR      0x00000000000f6ba9
#define memory_region_get_container_ADDR 0x00000000000f6c38
#define memory_region_get_priority_ADDR  0x00000000000f6d48

#define property_set_str_ADDR         0x000000000038834e
#define property_set_bool_ADDR        0x000000000038858c
#define property_set_enum_ADDR        0x00000000003887d4
#define property_set_alias_ADDR       0x0000000000388fb5
#define object_set_link_property_ADDR 0x0000000000387a58

#define memory_region_resolve_container_ADDR 0x00000000000f6d00
#define object_resolve_child_property_ADDR   0x000000000038768f
#define object_resolve_link_property_ADDR    0x0000000000387b9c
#define object_resolve_child_property_ADDR   0x000000000038768f
#define property_resolve_alias_ADDR          0x0000000000388ffa

#define property_release_alias_ADDR         0x0000000000389032
#define property_release_bootindex_ADDR     0x00000000000ee2f3
#define property_release_str_ADDR           0x00000000003883fa
#define property_release_bool_ADDR          0x000000000038862f
#define property_release_enum_ADDR          0x000000000038885f
#define property_release_tm_ADDR            0x0000000000388b90
#define object_release_link_property_ADDR   0x0000000000387bc0
#define object_finalize_child_property_ADDR 0x00000000003876a5

