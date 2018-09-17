#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pcontainer.h>

int devfd;

/**
 * main function to debug kernel with help of ioctl 
 */
int main(int argc, char *argv[])
{   
    // open the kernel module
    devfd = open("/dev/pcontainer", O_RDWR);
    if (devfd < 0)
    {
        fprintf(stderr, "Device open failed\n");
        exit(1);
    }
    fprintf(stderr, "Opened the kernel module for debugging");
    // allocate/associate a container for the thread.
    pcontainer_debug(devfd, 0);
    return 0;
}
