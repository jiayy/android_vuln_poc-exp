#define TEXT_ADDR           0x00000000000a9f60
#define mprotect_ADDR       
#define madvise_ADDR        
#define malloc_ADDR         
#define open_ADDR           
#define close_ADDR          
#define read_ADDR           
#define write_ADDR          
#define dup2_ADDR           
#define pipe_ADDR           
#define select_ADDR         
#define fork_ADDR           
#define execv_ADDR          
#define system_ADDR         
#define pthread_create_ADDR 
#define qemu_set_irq_ADDR   0x00000000002855c1

#define property_get_alias_ADDR          0x0000000000392a2a
#define property_get_enum_ADDR           0x00000000003921e8
#define property_get_tm_ADDR             0x0000000000392432
#define property_get_uint32_ptr_ADDR     0x0000000000392826
#define property_get_uint8_ptr_ADDR      0x000000000039275d
#define property_get_bool_ADDR           0x0000000000391fb0
#define property_get_str_ADDR            0x0000000000391d59
#define property_get_uint8_ptr_ADDR      0x000000000039275d
#define property_get_uint16_ptr_ADDR     0x00000000003927c1
#define property_get_uint32_ptr_ADDR     0x0000000000392826
#define property_get_uint64_ptr_ADDR     0x0000000000392889
#define object_get_link_property_ADDR    0x00000000003912d0
#define object_get_child_property_ADDR   0x00000000003910a9
#define memory_region_get_size_ADDR      0x00000000000fb77d
#define memory_region_get_addr_ADDR      0x00000000000fb504
#define memory_region_get_container_ADDR 0x00000000000fb594
#define memory_region_get_priority_ADDR  0x00000000000fb6a5

#define property_set_str_ADDR         0x0000000000391deb
#define property_set_bool_ADDR        0x000000000039202c
#define property_set_enum_ADDR        0x0000000000392277
#define property_set_alias_ADDR       0x0000000000392a70
#define object_set_link_property_ADDR 0x00000000003914f3

#define memory_region_resolve_container_ADDR 0x00000000000fb65d
#define object_resolve_child_property_ADDR   0x0000000000391127
#define object_resolve_link_property_ADDR    0x0000000000391637
#define object_resolve_child_property_ADDR   0x0000000000391127
#define property_resolve_alias_ADDR          0x0000000000392ab6

#define property_release_alias_ADDR         0x0000000000392aee
#define property_release_bootindex_ADDR     0x00000000000f2c2d
#define property_release_str_ADDR           0x0000000000391e97
#define property_release_bool_ADDR          0x00000000003920cf
#define property_release_enum_ADDR          0x0000000000392303
#define property_release_tm_ADDR            0x0000000000392640
#define object_release_link_property_ADDR   0x000000000039165b
#define object_finalize_child_property_ADDR 0x000000000039113d

