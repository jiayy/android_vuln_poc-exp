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
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "mtk/cmdq_v3_driver.h"
#include "mtk/cmdq_def.h"
 
#define CMDQ_INST_SIZE 8
#define TRACE_FILE       "/data/local/tmp/mtksu/raw"
#define CMD_FILE         "/data/local/tmp/mtksu/cmd"
#define ADDR_VALUES_FILE "/data/local/tmp/mtksu/values"

typedef long (*syscall_t)(long number, ...);
syscall_t real_syscall = NULL;
uint32_t cmd_num = 0;
uint32_t startPA = 0;
uint32_t countPA = 0;

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

// interpret and dump commands
static void dump_interp_cmd(struct cmdqCommandStruct* cmd)
{
    char fname[50];
    sprintf(fname, "%s-%d", CMD_FILE, cmd_num);
    FILE* f = fopen(fname, "w");
    uint32_t count = 0;
    while (count < (cmd->blockSize)) {
        uint32_t argb = *(uint32_t*)(cmd->pVABase + count);
        count += 4;
        uint32_t arga = *(uint32_t*)(cmd->pVABase + count);
        count += 4;
        int code = (arga & 0xff000000) >> 24;
        arga = arga & ~(0xff000000);
        switch (code) {
            case CMDQ_CODE_READ:
            case CMDQ_CODE_WRITE:
            {
                short typeb = ((arga & 0x800000) >> 23);
                short typea = ((arga & 0x400000) >> 22);
                short subsys = ((arga >> 16) & 0x1f);

                if (code == CMDQ_CODE_WRITE)
                    fprintf(f, "WRITE ");
                else if (code == CMDQ_CODE_READ)
                    fprintf(f, "READ ");
                else
                    fprintf(f, "POLL ");

                /* data value */
                if (typeb != 0)
                    argb = argb;
                else
                    argb = argb & 0xffff;

                /* address value */
                arga = subsys;

                fprintf(f, " address %s %x, data %s %x\n",
                        (typea != 0)?"reg":"mem",
                        arga,
                        (typeb != 0)?"reg":"mem",
                        argb);
            }
           break;
           case CMDQ_CODE_WFE:
           {
                uint16_t to_wait = ((argb >> 15) & 1);
                uint16_t to_update = ((argb >> 31) & 1);
                uint16_t wait    = (argb & 0xef);
                uint16_t update  = ((argb >> 16) & 0xef);
                fprintf(f, "WFE to_wait=%hx, wait=%hx, to_update=%hx, update=%hx, event=%x\n", to_wait, wait, to_update, update, arga);
            }
            break;
            case CMDQ_CODE_EOC:
                fprintf(f, "EOC %x %x\n", argb, arga);
            break;
            case CMDQ_CODE_JUMP:
                fprintf(f, "JUMP ");
                if ((arga & 0xffffff) != 0) {
                    fprintf(f, "(relative) ");
                    if (((int32_t)argb) >= 0)
                        fprintf(f, "+");
                    fprintf(f, "%d\n", argb);
                } else {
                    if ((arga & (1 << 22)) != 0)
                        fprintf(f, "reg %x %x\n", argb, arga & 0xffff);
                    else
                        fprintf(f, "addr %x %x\n", argb, arga & 0xffff);
                }
            break;
            case CMDQ_CODE_MOVE:
            {
                // test type
                if (1 & (arga >> 23)) {
                    short reg = ((arga >> 16) & 0x1f);
                    uint64_t dma = (uint64_t)((arga & 0xffff) << 32) | (uint64_t) argb;
                    if (dma >= startPA && dma <= startPA + countPA)
                        fprintf(f, "MOVE startPA+%x into reg %x\n", (uint32_t)dma-startPA, reg);
                    else    
                        fprintf(f, "MOVE %llx into reg %x\n", dma, reg);

                } else {
                    fprintf(f, "MOVE set MASK:0x%08x\n", argb);
                }
            }
            break;
            default:
                fprintf(f, "Unknown command %x\n", code);
            break;
        }
    }
    fclose(f);
}

// dump raw command
static void dump_raw_command(struct cmdqCommandStruct* cmd)
{   
    char fname[50];
    sprintf(fname, "%s-%d", TRACE_FILE, cmd_num);
    int f = open(fname, O_CREAT|O_WRONLY);
    write(f, cmd->pVABase, cmd->blockSize);
    close(f);
}

static void dump_addresses(struct cmdqReadAddressStruct *read_address, uint64_t addr)
{
    char* fname;
    asprintf(&fname, "%s-%d", ADDR_VALUES_FILE, addr);
    FILE* f = fopen(fname, "w");
    for (int i = 0; i < read_address->count; i++) {
        fwrite((uint32_t*)(read_address->values + (i * 4)), sizeof(uint32_t), 1, f);
    }
    fclose(f);
    free(fname);
}

void init ()
{
   real_syscall = dlsym(RTLD_NEXT, "syscall");
}

// syscall hook (ld_preload)
long syscall(long number, ...)
{

   va_list list;
   int count = 0;
   long ret = 0;
   void* args[8] = {0,};

   if (real_syscall == NULL)
        init();

   count = 7;

   va_start(list, count);

   // ioctl
   if (number == 0x36) {
       uint32_t fd = (uint32_t)va_arg(list, void*);
       uint32_t ioctl_num = (uint32_t)va_arg(list, void*);
       switch (ioctl_num) {
            case CMDQ_IOCTL_ALLOC_WRITE_ADDRESS:
                printf("alloc");
                struct cmdqWriteAddressStruct *wa = va_arg(list, void*);
                ret = real_syscall(number, fd, ioctl_num, wa);
                if (ret >= 0) {
                    startPA = wa->startPA;
                    countPA = wa->count;
                    printf(" count=%x startPA=0x%lx", wa->count, wa->startPA);
                }
                else
                    printf(" failed");
                printf("\n");
            break;
            case CMDQ_IOCTL_EXEC_COMMAND:
            {
                struct cmdqCommandStruct *c = (struct cmdqCommandStruct*)va_arg(list, void*);
#ifdef DUMP_RAW_COMMAND
                dump_raw_command(c);
#endif
                dump_interp_cmd(c);
                ret = real_syscall(number, fd, ioctl_num, c);
                printf("exec command (num %d) ( blockSize=%x, readAddress.count=%x ) dumped into cmd-%d\n", cmd_num, (uint32_t)c->blockSize, c->readAddress.count, cmd_num);
#ifdef DUMP_READADDRESS_VALUES
                    dump_addresses(&c->readAddress, dump_file);
#endif
                cmd_num++;
            }
            break;
            default:
                printf("uncatched ioctl %x\n", ioctl_num);
                ret = real_syscall(number, fd, ioctl_num, va_arg(list, void*),  va_arg(list, void*), va_arg(list, void*), va_arg(list, void*), va_arg(list, void*));
            break;
       }
   } else
       ret = real_syscall(number, va_arg(list, void*), va_arg(list, void*),  va_arg(list, void*), va_arg(list, void*), va_arg(list, void*), va_arg(list, void*)); // default syscall with 7 args

   fflush(stdout);
   va_end(list);
   return ret;
}
