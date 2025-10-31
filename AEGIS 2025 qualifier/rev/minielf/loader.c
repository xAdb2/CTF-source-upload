// loader.c
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv){
    void *h = dlopen("./chal1", RTLD_NOW);
    if(!h){ fprintf(stderr,"dlopen failed: %s\n", dlerror()); return 1; }
    // optional: call exported symbol if exists
    return 0;
}
