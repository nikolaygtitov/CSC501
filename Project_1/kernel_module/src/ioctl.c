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
struct task *cur_task;
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
 * Get the task within the given container and pid of the process.
 * If the task does not exist, NULL is returned.
 */
static struct task * get_task(struct container *container, __u64 pid)
{
    struct task *task = NULL;
    list_for_each_entry(task, &container->task_list, list) {
        if (task->pid == pid) {
            return task;
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
 * Find next task to run within the same container or if there are no remaining task within a given container, get first task from next container
 * 
 * Need to confirm with Nathan!
 */
static struct task * get_next_task(struct task *task)
{
    /** struct list_head *next_container_list_head = NULL;
    struct container *next_container = NULL; */
    struct task *next_task = task->list.next;
    
    /* Get next task from next container only if there are no more tasks within current container 
       Need to uncomment the code below if we agree to do so!!!!!
     */
    
    /* if (!next_task) { */
        /* Get next container */
        /* next_container_list_head = task->container->list.next;
        if (next_container_list_head == &container_list) { */
            /* Wrap back to beginning */
            /* next_container_list_head = next_container_list_head->next; */
        /* }
        next_container = (struct container *) list_entry(next_container_list_head, struct container, list); */
        
        /* Get first task from next container */
        /* next_task = (struct task *) list_entry(next_container->task_list.next, struct task, list); */
    /*}*/
    
    return next_task;
}

/**
 * Delete the task in the container.
 * 
 * external functions needed:
 * mutex_lock(), mutex_unlock(), wake_up_process(), 
 */
int processor_container_delete(struct processor_container_cmd __user *user_cmd)
{   
    struct container *container = NULL;
    struct task *task, *next_task = NULL;

    D("d");
    DEBUG("Called delete(%d), pid:%d\n", (unsigned)user_cmd->cid, current->pid);

    mutex_lock(&lock);
    /* Find container with given cid */
    container = get_container(user_cmd->cid);
    if (!container) {
        printk(KERN_ERR "No such CID: %d is found in the container list.\n", (unsigned) user_cmd->cid);
        D("!1");
        mutex_unlock(&lock);
        return EINVAL;
    }
    
    DEBUG("Container found, Container: %d.\n Attempt to find a task...\n", (unsigned) container->cid);

    /* Find task only if current task is NULL or current task does not match the running task*/
    if (cur_task && cur_task->pid == current->pid) {
        DEBUG("Start Deleting.\n Current Task is found, TID: %d.\nAttempt to schedule next task...\n", (unsigned) cur_task->pid);
        task = cur_task;
    } else {
        DEBUG("Start Deleting.\n Current Task is NULL, attempt to find current running task in container (%d), pid:%d\n", (unsigned)user_cmd->cid, current->pid);
        /* Find a task within a given container based on current task_struct */
        task = get_task(container, current->pid);
        if (!task) {
            printk(KERN_ERR "No such task with PID: %d is found in the container with CID: %d.\n", (unsigned) current->pid, (unsigned) container->cid);
            D("!2");
            mutex_unlock(&lock);
            return EINVAL;
        }
        DEBUG("Task found, TID: %d.\nAttempt to schedule next task...\n", (unsigned) task->pid);
    }
    
    next_task = get_next_task(task);

    /* Schedule next task */
    if (next_task) {
        DEBUG("Next task found. Attempt to wake up, TID: %d\n", (unsigned) next_task->pid);
        DEBUG("Waking up task: %d\n", next_task->pid);
        D("(");
        while(wake_up_process(next_task->task_struct) == 0) {
            D(".")
        }
        D(")");
        cur_task = next_task;
        DEBUG("Next task is awaken and it becomes current task, TID: %d\n", (unsigned) cur_task->pid);
    } else {
        DEBUG("Next task NOT found assign current task to NULL, found task, TID:%d\n", task->pid);
        cur_task = NULL;
    }

    /* Delete the task from the container */
    DEBUG("Deleting task from container, CID: %d, TID: %d\n", (unsigned) container->cid, (unsigned) task->pid);
    list_del(&task->list);
    DEBUG("Deleted task: %d\n", task->pid);

    /* Free task */
    DEBUG("Freeing task, TID: %d\n", (unsigned) task->pid);
    kfree(task);
    
    /* If container does not have anymore tasks in it, remove container */
    if (list_empty(&container->task_list)) {
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

    D("c");
    DEBUG("Called create(%d), pid:%d\n", (unsigned)user_cmd->cid, current->pid);

    mutex_lock(&lock);

    /* Find container with given cid */
    container = get_container(user_cmd->cid);
    if (!container) {
        /* Could not find container in list - create it */
        container = create_container(user_cmd->cid);
        if (!container) {
            printk(KERN_ERR "Unable to create container\n");
            D("!3");
            mutex_unlock(&lock);
            return -1;
        }
    }

    /* Create task */
    task = create_task(container, current);

    /* Set cur_task if this is the first task */
    if (!cur_task) {
        cur_task = task;
        mutex_unlock(&lock);
    } else {
        mutex_unlock(&lock);
        /* Deschedule new task */
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    }

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
    struct task *prev_task = NULL;
    struct task *next_task = NULL;

    D("s");
    DEBUG("Called switch(%d), pid:%d\n", (unsigned)user_cmd->cid, current->pid);

    mutex_lock(&lock);

    /* Only switch if current running process is cur_task, otherwise find correct cur_task */
    if (!cur_task || cur_task->pid != current->pid) {
        /* Find container with given cid */
        container = get_container(user_cmd->cid);
        if (!container) {
            printk(KERN_ERR "No such CID: %d is found in the container list.\n", (unsigned) user_cmd->cid);
            D("!1");
            mutex_unlock(&lock);
            return EINVAL;
        }
        cur_task = get_task(container, current->pid);
        if (!cur_task) {
            printk(KERN_ERR "No such task with PID: %d is found in the container with CID: %d.\n", (unsigned) current->pid, (unsigned) container->cid);
            D("!4");
            mutex_unlock(&lock);
            return EINVAL;
        }
    }

    /* Get the next task within the same container or if no more tasks in the container get first task from the next container */
    /* OR */
    /* Get the next task within the same container or if no more tasks in the container do not switch*/
    next_task = get_next_task(cur_task);

    if (next_task && next_task->pid != cur_task->pid) {
        prev_task = cur_task;
        cur_task = next_task;
        mutex_unlock(&lock);
        
        /* Move task to running state */
        DEBUG("Switching task: %d:%d->%d:%d\n", 
                (unsigned)prev_task->container->cid, prev_task->pid,
                (unsigned)next_task->container->cid, next_task->pid);
        //wake_up_process(next_task->task_struct);
        D("<");
        while(wake_up_process(next_task->task_struct) == 0) {
            D(".")
        }

        DEBUG("Switch is successful: %d:%d->%d:%d\n", 
                (unsigned)prev_task->container->cid, prev_task->pid,
                (unsigned)next_task->container->cid, next_task->pid);

        /* De-schedule previous task */
        set_current_state(TASK_INTERRUPTIBLE);
        DEBUG("Sleeping: %d\n", current->pid);
        D(">");
        schedule();
    } else {
        mutex_unlock(&lock);
        DEBUG("Cannot switch task - no remaining tasks in the container except current task : %d:%d\n", 
                (unsigned)cur_task->container->cid, cur_task->pid);
    }
    D("-");

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

    /* Print current task */
    DEBUG("CURRENT TASK:%s\n", "");
    debug_print_task(cur_task);

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
