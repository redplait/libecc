fork of [libecc](https://github.com/ANSSI-FR/libecc) patched for WDK7

### what problems were solved?
usage of C99. cl from WDK7 is very old and does not have support of C99

High stack usage. Authors of original library diligently avoided memory allocations so functions like XXX_verify_finalize used above 4Kb of stack. I add in sig/sig_algs_internal.h pairs of fptr for memory allocation/freeing

### Building
just run Build Environment from WDK7 and run nmake
It seems that WDK7 does not have lib.exe so I used one from VS2017