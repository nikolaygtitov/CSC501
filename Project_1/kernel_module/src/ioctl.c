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

#define DEBUG(format, ...) printk(KERN_DEBUG "[pid:%d][csc501:%s:%d]: " format, current->pid, __func__, __LINE__, __VA_ARGS__)
#define DBUF_LEN 8192
#define D(str) strncat(dbuf, str, DBUF_LEN);

struct container {
    __u64 cid;
    struct list_head list;
    struct list_head task_list;
};

struct task {
    pid_t pid;
    struct task_struct *task_struct;
    struct container *container;
    struct list_head list;
};

DEFINE_MUTEX(lock);
LIST_HEAD(container_list);
char dbuf[DBUF_LEN] = "\0";

/**
 * Get the container with the given cid.
 * If the container does not exist, NULL is returned.
 */
static struct container * get_container(__u64 cid)
{
    struct container *container = NULL;
    list_for_each_entry(container, &container_list, list) {
        if (container->cid == cid) {
            return container;
        }
    }
    return NULL;
}

/**
 * Get the task for a given pid of the process. Since the running task of each 
 * container is the first task in the list, iterate through containers and 
 * check only the first task in the list.
 * If the task does not exist, NULL is returned.
 */
static struct task * get_task(__u64 pid)
{
    struct container *container = NULL;
    struct task *task = NULL;
    list_for_each_entry(container, &container_list, list) {
        task = (struct task *) list_entry(container->task_list.next, struct task, list);
        if (task->pid == pid) {
            return task;
        }
    }
    return NULL;
}

/**
 * Find next task to run within the same container. It moves the current task 
 * to the end of the least, regardless if there are other tasks or not, and 
 * gets the first task from the list, which is:
 *     1) The next task that should be run
 *     2) The same task that is already running
 */
static struct task * get_next_task(struct task *task)
{
    struct task *next_task = NULL;
    list_move_tail(&task->list, &task->container->task_list);
    next_task = (struct task *) list_entry(task->container->task_list.next, struct task, list);
    return next_task;
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

    container->cid = cid;

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
static struct task * create_task(struct container *container, struct task_struct *task_struct)
{
    struct task *task = NULL;

    /* Allocate task */
    task = (struct task *) kcalloc(1, sizeof(struct task), GFP_KERNEL);
    if (!task) {
        return NULL;
    }

    /* Set task fields */
    task->pid = task_struct->pid;
    task->task_struct = task_struct;
    task->container = container;

    /* Initialize task list head */
    INIT_LIST_HEAD(&task->list);

    /* Add to container task list */
    list_add_tail(&task->list, &container->task_list);

    DEBUG("Added task %d:%d\n", (unsigned)container->cid, (unsigned) task->pid);

    return task;
}

/**
 * Delete the task in the container.
 * Find currently running task based on pid. The first task in the task list of 
 * the container is always a currently running task. Iterate over containers 
 * and only check first tasks of each container.
 * If the task is the only remaining task in the task list of the container, do 
 * not wake up any other tasks, delete the task, and delete the container.
 * Otherwise, find next task to run, delete the current task, and wake up next 
 * task.
 * 
 * external functions needed:
 * mutex_lock(), mutex_unlock(), wake_up_process(), 
 */
int processor_container_delete(struct processor_container_cmd __user *user_cmd)
{
    struct container *container = NULL;
    struct task *task, *next_task = NULL;
    __u64 cid;

    mutex_lock(&lock);
    // cid = (__u64 *) kcalloc(1, sizeof(__u64), GFP_KERNEL);
    if (copy_from_user(&cid, user_cmd->cid, sizeof(__u64))) {
        printk(KERN_ERR "Copy from user of the container CID failure on PID: %d.\n", (unsigned) current->pid);
        mutex_unlock(&lock);
        return -EFAULT;
    }
    DEBUG("Called delete(%d), pid:%d\n", cid, current->pid);
    DEBUG("Attempt to find a task by checking first task of each container: CID:%d, PID:%d...\n", cid, current->pid);

    /* Find a task by checking only first task of each container since first task in the task list of a container is always running task */
    task = get_task();
    if (!task) {
        printk(KERN_ERR "No such running task with PID: %d is found in existing containers.\n", (unsigned) current->pid);
        mutex_unlock(&lock);
        return EINVAL;
    }
    
    DEBUG("Task found, TID: %d.\nAttempt to wake up next task...\n", (unsigned) task->pid);
    
    next_task = get_next_task();
    if (!next_task) {
        printk(KERN_ERR "Next task NOT found due to incorrect list operation. "
               "Current task with TID: %d in container CID: %d cannot have "
               "next task as NULL.\n", (unsigned) task->pid, cid);
        mutex_unlock(&lock);
        return EINVAL;
    }

    /* Wake up next task only if next task exists; otherwise, find container that needs to be removed */
    if (next_task->pid != task->pid) {
        DEBUG("Next task found in the container CID: %d. Attempt to wake up, TID: %d...\n", cid, (unsigned) next_task->pid);
        while(wake_up_process(next_task->task_struct) == 0);
        DEBUG("Next task is awaken, TID: %d\nAttempt to delete task...\n", (unsigned) next_task->pid);
    } else {
        DEBUG("Only single task in a container CID: %d found with TID:%d. "
                "There is no next task. Attempt to find a container...\n", 
                cid, task->pid);
        /* Find container with given cid since it has to be removed */
        container = get_container(cid);
        if (!container) {
            printk(KERN_ERR "No such CID: %d is found in the container list.\n", cid);
            mutex_unlock(&lock);
            return EINVAL;
        }
        DEBUG("Container found, Container: %d.\nAttempt to delete task and then its container...\n", cid);
    }

    /* Delete the task from the container */
    DEBUG("Deleting task from container, CID: %d, TID: %d\n", cid, (unsigned) task->pid);
    list_del(&task->list);
    DEBUG("Deleted task: %d\n", (unsigned) task->pid);

    /* Free task */
    DEBUG("Freeing task, TID: %d\n", (unsigned) task->pid);
    kfree(task);
    
    /* If container does not have anymore tasks in it, remove container */
    if (container && list_empty(&container->task_list)) {
        DEBUG("Container does not have anymore tasks in it - remove it, CID: %d\n", (unsigned) container->cid);
        list_del(&container->list);
        DEBUG("Deleted container: %d\n", (unsigned)container->cid);
        kfree(container);
    }
    mutex_unlock(&lock);
    return 0;
}

/**
 * Create a task in the corresponding container.
 * Check if container already exists. If it does not exist, create new 
 * container. 
 * Create new task. Insert new task at the end of the task list of the 
 * container.
 * If new task is the only task in the container, let it run. Otherwise, put it 
 * to sleep.
 * 
 * external functions needed:
 * copy_from_user(), mutex_lock(), mutex_unlock(), set_current_state(), schedule()
 * 
 * external variables needed:
 * struct task_struct* current  
 */
int processor_container_create(struct processor_container_cmd __user *user_cmd)
{
    struct container *container = NULL;
    struct task *task = NULL;
    __u64 cid;

    mutex_lock(&lock);
    // cid = (__u64 *) kcalloc(1, sizeof(__u64), GFP_KERNEL);
    if (copy_from_user(&cid, user_cmd->cid, sizeof(__u64))) {
        printk(KERN_ERR "Copy from user of the container CID failure on PID: %d.\n", (unsigned) current->pid);
        mutex_unlock(&lock);
        return -EFAULT;
    }

    DEBUG("Called create(%d), pid:%d.\n", (unsigned) cid, current->pid);

    /* Find container with given cid */
    container = get_container(cid);
    if (!container) {
        /* Could not find container in list - create it */
        DEBUG("Container not found, CID: %d. Attempt to create new container...\n", cid);
        container = create_container(cid);
        if (!container) {
            printk(KERN_ERR "Unable to create container.\n");
            mutex_unlock(&lock);
            return EINVAL;
        }
        DEBUG("Container is created, CID: %d. Attempt to create new task...\n", cid);
        /* Create task */
        task = create_task(container, current);
        if (!task) {
            printk(KERN_ERR "Unable to create task.\n");
            mutex_unlock(&lock);
            return EINVAL;
        }
        /* Since this is the first task in the container, let it run */
        DEBUG("The very first task is created and stored in the task list of a new container, CID: %d, TID: %d.\n"
                "Let this task run.\n", cid, (unsigned) task->pid);
        mutex_unlock(&lock);
    } else {
        DEBUG("Container found, CID: %d. Attempt to create new task...\n", cid);
        /* Create task */
        task = create_task(container, current);
        if (!task) {
            printk(KERN_ERR "Unable to create task.\n");
            mutex_unlock(&lock);
            return EINVAL;
        }
        /* This is not the first task in the container, put it to sleep */
        DEBUG("Additional task is created and stored in the task list of the existing container, CID: %d, TID: %d.\n"
                "Put this task to sleep.\n", cid, (unsigned) task->pid);
        mutex_unlock(&lock);
        /* De-schedule new task */
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    }
    
    return 0;
}

/**
 * Switch to the next task in the same container.
 * Find currently running task based on pid. Since the first task in the task 
 * list of the container is always a currently running task, iterate over 
 * containers and only check first tasks of each container.
 * Find next task to run and if there exists next task in a container, move 
 * currently running task to the end of the task list of a container, wake up 
 * next task (that currently placed as the first task in the task list of a 
 * container) and put to sleep currently running process.
 * Otherwise, let the current task continue to run.
 * 
 * external functions needed:
 * mutex_lock(), mutex_unlock(), wake_up_process(), set_current_state(), schedule()
 */
int processor_container_switch(struct processor_container_cmd __user *user_cmd)
{
    struct task *task, *next_task = NULL;
    __u64 cid;

    mutex_lock(&lock);
    // cid = (__u64 *) kcalloc(1, sizeof(__u64), GFP_KERNEL);
    if (copy_from_user(&cid, user_cmd->cid, sizeof(__u64))) {
        printk(KERN_ERR "Copy from user of the container CID failure on PID: %d.\n", (unsigned) current->pid);
        mutex_unlock(&lock);
        return -EFAULT;
    }

    DEBUG("Called switch(%d), pid:%d\n", cid, current->pid);

    /* Find a task by checking only first task of each container. 
     * First task in the task list of a container is always running task */
    task = get_task();
    if (!task) {
        printk(KERN_ERR "No such running task with PID: %d is found in existing containers.\n", (unsigned) current->pid);
        mutex_unlock(&lock);
        return EINVAL;
    }

    DEBUG("Task found, TID: %d.\nAttempt to schedule next task...\n", (unsigned) task->pid);
    
    /* Get the next task in the same container and switch or 
     * if there are no more tasks in the container do not switch */
    next_task = get_next_task(task);
    if (!next_task) {
        printk(KERN_ERR "Next task NOT found due to incorrect list operation. "
               "Current task with TID: %d in container CID: %d cannot have "
               "next task as NULL.\n", (unsigned) task->pid, cid);
        mutex_unlock(&lock);
        return EINVAL;
    }

    if (next_task->pid != task->pid) {
        DEBUG("Next task found in container CID: %d. Attempt to perform switch, TID:%d->TID:%d...\n", 
                cid, (unsigned) next_task->pid);
        
        /* Move task to running state */
        DEBUG("Switching task: %d->%d\n", task->pid, next_task->pid);
        while(wake_up_process(next_task->task_struct) == 0);
        DEBUG("Switch is successful: %d->%d\n", task->pid, next_task->pid);
        
        mutex_unlock(&lock);

        /* De-schedule previous task */
        set_current_state(TASK_INTERRUPTIBLE);
        DEBUG("Sleeping: %d\n", task->pid);
        schedule();
    } else {
        DEBUG("Only single task in a container CID: %d found with TID: %d. "
                "There is no next task.\nDo not switch.\n", cid, task->pid);
        mutex_unlock(&lock);
    }

    return 0;
}

static void debug_print_task(struct task *task)
{
    if (!task) {
        DEBUG("  NULL%s\n", "");
    } else {
        DEBUG("  TASK: %d\n", task->pid);
        DEBUG("    State: %d\n", (int)task->task_struct->state);
    }
}

static void debug_print_container(struct container *container)
{
    struct task *task = NULL;
    DEBUG("CONTAINER: %d\n", (unsigned)container->cid);
    /* Print container data */
    list_for_each_entry(task, &container->task_list, list) {
        debug_print_task(task);
    }
}

/**
 * Print debug information
 */
int processor_container_debug(struct processor_container_cmd __user *user_cmd)
{
    int locked = 0;
    struct container *container = NULL;

    /* Print mutex state and lock if possible - don't bother if someone is holding the lock */
    locked = mutex_trylock(&lock);
    if (!locked) {
        DEBUG("Unable to acquire mutex: %p\n", &lock);
    } else {
        DEBUG("Mutex acquired: %p\n", &lock);
    }

    /* Print current task 
    DEBUG("CURRENT TASK:%s\n", "");
    debug_print_task(cur_task);
     */

    /* Print container data */
    list_for_each_entry(container, &container_list, list) {
        debug_print_container(container);
    }

    D(";");
    DEBUG("DBUF: %s\n", dbuf);

    /* Unlock if we successfully locked */
    if (locked) {
        mutex_unlock(&lock);
        DEBUG("Mutex released: %p\n", &lock);
    }
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
    case PCONTAINER_IOCTL_DEBUG:
        return processor_container_debug((void __user *)arg);
    default:
        return -ENOTTY;
    }
}
