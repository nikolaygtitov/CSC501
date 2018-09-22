#include "pcontainer.h"

/**
 * context switch handler in user space that sends command to kernel space
 * for switch tasks and containers.
 */
int pcontainer_context_switch_handler(int devfd, int id)
{
    struct processor_container_cmd cmd;
    cmd.cid = id;
//    fprintf(stderr, "%d: switch\n", (int)syscall(SYS_gettid));
    return ioctl(devfd, PCONTAINER_IOCTL_CSWITCH, &cmd);
}

/**
 * delete function in user space that sends command to kernel space
 * for deleting the current task in specified container.
 */
int pcontainer_delete(int devfd, int id)
{
    struct processor_container_cmd cmd;
    cmd.cid = id;
    return ioctl(devfd, PCONTAINER_IOCTL_DELETE, &cmd);
}

/**
 * create function in user space that sends command to kernel space
 * for creating the current task in specified container.
 */
int pcontainer_create(int devfd, int id)
{
    struct processor_container_cmd cmd;
    cmd.cid = id;
    return ioctl(devfd, PCONTAINER_IOCTL_CREATE, &cmd);
}

/**
 * create function in user space that sends command to kernel space
 * for debugging purposes of kernel and ioctl to dump all containers and task.
 */
int pcontainer_debug(int devfd, int id)
{
    struct processor_container_cmd cmd;
    cmd.cid = id;
    return ioctl(devfd, PCONTAINER_IOCTL_DEBUG, &cmd);
}
