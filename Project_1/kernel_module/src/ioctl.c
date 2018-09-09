//////////////////////////////////////////////////////////////////////
//                      North Carolina State University
//
//
//
//                             Copyright 2016
//
////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
// This program is distributed in the hope it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
//
////////////////////////////////////////////////////////////////////////
//
//   Author:  Hung-Wei Tseng, Yu-Chia Liu
//
//   Description:
//     Core of Kernel Module for Processor Container
//
////////////////////////////////////////////////////////////////////////

#include "processor_container.h"

#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/mutex.h>

#define DEBUG(format, ...) printk(KERN_ERR "[%s]: " format, __func__, __VA_ARGS__)

struct container {
    __u64 cid;
    struct list_head list;
    struct list_head task_list;
};

struct task {
    pid_t pid;
    struct list_head list;
};

struct mutex lock;

struct list_head container_list;

/**
 * Get the container with the given cid.
 * If the container does not exist, NULL is returned.
 */
static struct container * get_container(__u64 cid)
{
    struct list_head *list_itr = NULL;
    struct container *container = NULL;
    list_for_each(list_itr, &container_list) {
        container = (struct container *) list_entry(list_itr, struct container, list);
        if (container->cid == cid) {
            return container;
        }
    }
    return NULL;
}

/**
 * Create a new container.
 */
static struct container * create_container(__u64 cid)
{
    struct container *container = NULL;

    /* Allocate container */
    container = (struct container *) kcalloc(1, sizeof(struct container), GFP_KERNEL);
    if (!container) {
        return NULL;
    }

    /* Initialize container list head */
    INIT_LIST_HEAD(&container->list);

    /* Initialize task list head */
    INIT_LIST_HEAD(&container->task_list);

    /* Add container to list */
    list_add_tail(&container->list, &container_list);

    DEBUG("Created container %d\n", (unsigned) cid);

    return container;
}

/**
 * Create task.
 */
static struct task * create_task(struct container *container, struct task_struct *thread)
{
    struct task *task = NULL;

    /* Allocate task */
    task = (struct task *) kcalloc(1, sizeof(struct task), GFP_KERNEL);
    if (!task) {
        return NULL;
    }

    /* Set task fields */
    task->pid = thread->pid;

    /* Initialize task list head */
    INIT_LIST_HEAD(&task->list);

    /* Add to container task list */
    list_add_tail(&task->list, &container->task_list);

    return task;
}

/**
 * Delete the task in the container.
 * 
 * external functions needed:
 * mutex_lock(), mutex_unlock(), wake_up_process(), 
 */
int processor_container_delete(struct processor_container_cmd __user *user_cmd)
{
    return 0;
}

/**
 * Create a task in the corresponding container.
 * external functions needed:
 * copy_from_user(), mutex_lock(), mutex_unlock(), set_current_state(), schedule()
 * 
 * external variables needed:
 * struct task_struct* current  
 */
int processor_container_create(struct processor_container_cmd __user *user_cmd)
{
    struct container *container = NULL;
    mutex_lock(&lock);

    /* Find container with given cid */
    container = get_container(user_cmd->cid);
    if (!container) {
        /* Could not find container in list - create it */
        container = create_container(user_cmd->cid);
        if (!container) {
            printk(KERN_ERR "Unable to create container\n");
            mutex_unlock(&lock);
            return -1;
        }
    }

    /* Create task */
    (void) create_task(container, current);

    mutex_unlock(&lock);
    return 0;
}

/**
 * switch to the next task in the next container
 * 
 * external functions needed:
 * mutex_lock(), mutex_unlock(), wake_up_process(), set_current_state(), schedule()
 */
int processor_container_switch(struct processor_container_cmd __user *user_cmd)
{
    return 0;
}

/**
 * control function that receive the command in user space and pass arguments to
 * corresponding functions.
 */
int processor_container_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg)
{
    switch (cmd)
    {
    case PCONTAINER_IOCTL_CSWITCH:
        return processor_container_switch((void __user *)arg);
    case PCONTAINER_IOCTL_CREATE:
        return processor_container_create((void __user *)arg);
    case PCONTAINER_IOCTL_DELETE:
        return processor_container_delete((void __user *)arg);
    default:
        return -ENOTTY;
    }
}
