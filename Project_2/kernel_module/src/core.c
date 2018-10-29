// Project 2: Nathan Schnoor, nfschnoo; Nikolay Titov, ngtitov;

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
//   Author:  Hung-Wei Tseng, Yu-Chia Liu, Nathan Schnoor, Nikolay Titov
//
//   Description:
//     Core of Kernel Module for Memory Container
//
////////////////////////////////////////////////////////////////////////

#include "memory_container.h"

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

extern struct miscdevice memory_container_dev;
extern struct mutex c_lock;
extern struct list_head container_list;

struct container {
    __u64 cid;
    struct list_head list;
    struct list_head task_list;
    struct list_head object_list;
};

struct task {
    pid_t pid;
    struct task_struct *task_struct;
    struct container *container;
    struct list_head list;
};

struct object {
    __u64 oid;
    char *shared_memory;
    unsigned long size;
    unsigned long pfn;
    unsigned waiting_threads;
    struct mutex lock;
    struct list_head list;
};

/**
 * Initialize and register the kernel module
 */
int memory_container_init(void)
{
    int ret;

    if ((ret = misc_register(&memory_container_dev))) {
        printk(KERN_ERR "Unable to register \"memory_container\" misc device\n");
    }
    else {
        mutex_init(&c_lock);
        INIT_LIST_HEAD(&container_list);
        printk(KERN_ERR "\"memory_container\" misc device installed\n");
        printk(KERN_ERR "\"memory_container\" version 0.1\n");   
    }
    return ret;
}

/**
 * Cleanup and deregister the kernel module
 */ 
void memory_container_exit(void)
{
    /* Free all resources */
    struct container *container, *ncontainer = NULL;
    struct task *task, *ntask = NULL;
    struct object *object, *nobject = NULL;
    list_for_each_entry_safe(container, ncontainer, &container_list, list) {
        /* Free tasks */
        list_for_each_entry_safe(task, ntask, &container->task_list, list) {
            list_del(&task->list);
            kfree(task);
        }
        /* Free objects */
        list_for_each_entry_safe(object, nobject, &container->object_list, list) {
            if (object->shared_memory) {
                kfree(object->shared_memory);
            }
            list_del(&object->list);
            kfree(object);
        }
        /* Delete container */
        list_del(&container->list);
        kfree(container);
    }

    misc_deregister(&memory_container_dev);
}
