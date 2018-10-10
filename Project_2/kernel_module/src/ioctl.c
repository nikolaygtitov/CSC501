// Project 2: Nathan Schnoor, nfschnoo; Nikolay Titov, ngtitov;

//////////////////////////////////////////////////////////////////////
//                      North Carolina State University
//
//
//
//                             Copyright 2018
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
#include <linux/kthread.h>

#define PCONTAINER_IOCTL_DEBUG _IOWR('N', 0x48, struct memory_container_cmd)
#define DEBUG(format, ...) printk(KERN_DEBUG "[pid:%d][csc501:%s:%d]: " format, current->pid, __func__, __LINE__, __VA_ARGS__)
#define ERROR(format, ...) printk(KERN_ERR "[pid:%d][csc501:%s:%d]: " format, current->pid, __func__, __LINE__, __VA_ARGS__)

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
    phys_addr_t p_addr;
    struct list_head list;
};

struct mutex c_lock;
struct list_head container_list;


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
static struct task * get_running_task(__u64 pid)
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
 * Get the running task for a given pid of the process.
 * Iterate through all the tasks in the container since this is unexpected 
 * task called switch. If this is unexpected task that is running, it needs to 
 * be put back to sleep.
 * If the task does not exist, NULL is returned.
 */
static struct task * get_task(__u64 pid)
{
    struct container *container = NULL;
    struct task *task = NULL;
    list_for_each_entry(container, &container_list, list) {
        list_for_each_entry(task, &container->task_list, list) {
            if (task->pid == pid) {
                return task;
            }
        }
    }
    return NULL;
}

/**
 * Get the object for a given container and object id (oid).
 */
static struct object * get_object(struct container *container, __u64 oid)
{
    struct object *object = NULL;
    list_for_each_entry(object, &container->object_list, list) {
        if (object->oid == oid) {
            return object;
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
    
    /* Initialize object list head */
    INIT_LIST_HEAD(&container->object_list);

    /* Add container to list */
    list_add_tail(&container->list, &container_list);

    DEBUG("Created container %llu\n", cid);

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

    /* Add this new task next to currently running task to the task list of the container */
    list_add(&task->list, container->task_list.next);

    DEBUG("Added task %llu:%d\n", container->cid, task->pid);

    return task;
}

/**
 * Create a VMM area memory object.
 * 
 * Insert the object into VMM area memory list of the memory container.
 */
static void create_object(struct container *container, struct vm_area_struct *vma)
{
    struct object *object = NULL;

    /* Allocate object */
    object = (struct object *) kcalloc(1, sizeof(struct object), GFP_KERNEL);
    if (!object) {
        return NULL;
    }

    /* Set object fields */
    object->oid = vma->vm_pgoff;
    /* Allocate requested size of the memory for object */
    object->shared_memory = kmalloc(vma->vm_pgoff, GFP_KERNEL);
    if (!object->requested_memory) {
        return NULL;
    }
    /* Map virtual address to physical */
    object->p_addr = virt_to_phys((void *) object->shared_memory);
    
    /* Initialize object list head */
    INIT_LIST_HEAD(&object->list);

    /* Add this new object to the end of the list of objects */
    list_add_tail(&object->list, &container->object_list);
    
    DEBUG("Added object OID: %llu into container CID: %llu.\n", object->oid, object->container->cid);

    return object;
    
}

int memory_container_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct task *task = NULL;
    struct object *object = NULL;

    DEBUG("Called mmap, pid:%d.\n", current->pid);

    /* Copy user data to kernel */
    if (copy_from_user(&kernel_vma, (void *) vma, sizeof(struct vm_area_struct))) {
        ERROR("Copy from user of the vma failure on PID: %d.\n", current->pid);
        return -EFAULT;
    }
    
    task = get_task(current->pid);
    if (!task) {
        ERROR("No such running task with PID: %d is found in existing containers.\n", current->pid);
        return ESRCH;
    }
    
    /* Find an object for a given container and object id */
    object = get_object(task->container, kernel_vma.vm_pgoff);
    
    if (!object) {
        /* Could not find object in the given container - create new object */
        DEBUG("No such object OID: %llu in the container CID: %llu. Attempt to create new object...\n", kernel_vma.vm_pgoff, task->container->cid);
        object = create_object(container, &kernel_vma);
        if (!object) {
            ERROR("Unable to create object OID: %llu in the container CID: %llu -> PID: %d due to memory allocation issues.\n", kernel_vma.vm_pgoff, task->container->cid, task->pid);
            return ENOMEM;
        }
    }
    
    /* Remap kernel memory into the user-space */
    if (remap_pfn_range(vma, vma->vm_start, object->p_addr, object->oid, object->vma->vm_page_prot) != 0) {
        ERROR("Failed: Unable to remap kernel memory into the user space; CID: %llu -> PID: %d -> OID: %llu due to memory allocation issues.\n", task->container->cid, task->pid, object->oid);
        return EADDRNOTAVAIL;
    }
    
    DEBUG("Success: Request to remap kernel space memory into the user-space memory; CID: %llu -> PID: %d -> OID: %llu.\n", task->container->cid, task->pid, object->oid);
    return 0;
}


int memory_container_lock(struct memory_container_cmd __user *user_cmd)
{
    mutex_lock(&c_lock);
    return 0;
}


int memory_container_unlock(struct memory_container_cmd __user *user_cmd)
{
    mutex_unlock(&c_lock);
    return 0;
}

/**
 * Delete the task in the container.
 * 
 * Finds currently running task based on pid. The first task in the task list of 
 * the container is always a currently running task. Iterate over containers 
 * and only check first tasks of each container.
 * If the task is the only remaining task in the task list of the container, do 
 * not wake up any other tasks, delete the task, and delete the container.
 * Otherwise, find next task to run, wake up next task, and delete the current 
 * task.
 * 
 * external functions needed:
 * mutex_lock(), mutex_unlock(), wake_up_process(), 
 */
int memory_container_delete(struct memory_container_cmd __user *user_cmd)
{
    struct task *task, *next_task = NULL;

    DEBUG("Called delete: pid:%d\n", current->pid);

    mutex_lock(&c_lock);
    /* Find a task by checking only first task of each container since first task in the task list of a container is always running task */
    task = get_running_task(current->pid);
    if (!task) {
        ERROR("No such running task with PID: %d is found in existing containers.\n", current->pid);
        mutex_unlock(&c_lock);
        return ESRCH;
    }
    
    next_task = get_next_task(task);
    if (!next_task) {
        ERROR("Next task NOT found due to incorrect list operation. "
              "Current task with TID: %d in container CID: %llu cannot have "
              "next task as NULL.\n", task->pid, task->container->cid);
        mutex_unlock(&c_lock);
        return ENOEXEC;
    }

    /* Wake up next task only if next task exists; otherwise, find container that needs to be removed */
    if (next_task->pid != task->pid) {
        DEBUG("Next task found in the container CID: %llu. Attempt to wake up, TID: %d...\n", next_task->container->cid, next_task->pid);
        while(wake_up_process(next_task->task_struct) == 0);
        DEBUG("Next task is awake, TID: %d\nAttempt to delete task...\n", next_task->pid);
    } else {
        DEBUG("Only single task in a container CID: %llu found with TID:%d. There is no next task...\n", task->container->cid, task->pid);
    }

    /* Delete the task from the container */
    list_del(&task->list);
    DEBUG("Deleted task: CID: %llu -> PID: %d. Attempt to free task...\n", task->container->cid, task->pid);
    
    /* If container does not have anymore tasks and objects in it, remove container */
    if (list_empty(&task->container->task_list) && list_empty(&task->container->object_list)) {
        list_del(&task->container->list);
        DEBUG("Container does not have anymore tasks nor objects. Deleted container from the list: %llu\n", task->container->cid);
        kfree(task->container);
    }
    
    /* Free task */
    DEBUG("Freeing task: CID: %llu -> PID: %d.\n", task->container->cid, task->pid);
    kfree(task);
    
    mutex_unlock(&c_lock);
    return 0;
}

/**
 * Create a task in the corresponding container.
 * 
 * Check if container already exists. If it does not exist, create new 
 * container. 
 * Create new task. Insert new task into the task list of the container.
 * If new task is the only task in the container, let it run.
 * Otherwise, put the newly created task to sleep.
 * 
 * external functions needed:
 * copy_from_user(), mutex_lock(), mutex_unlock(), set_current_state(), schedule()
 * 
 * external variables needed:
 * struct task_struct* current  
 */
int memory_container_create(struct memory_container_cmd __user *user_cmd)
{
    struct container *container = NULL;
    struct task *task = NULL;
    struct memory_container_cmd cmd;
    bool is_new_container = false;

    DEBUG("Called create, pid:%d.\n", current->pid);

    /* Copy user data to kernel */
    if (copy_from_user(&cmd, (void *) user_cmd, sizeof(struct memory_container_cmd))) {
        ERROR("Copy from user of the user_cmd failure on PID: %d.\n", current->pid);
        return -EFAULT;
    }

    mutex_lock(&c_lock);

    /* Find container with given cid */
    container = get_container(cmd.cid);
    if (!container) {
        /* Could not find container in list - create it */
        DEBUG("Container not found, CID: %llu. Attempt to create new container...\n", cmd.cid);
        container = create_container(cmd.cid);
        if (!container) {
            ERROR("Unable to create container %llu.\n", cmd.cid);
            mutex_unlock(&c_lock);
            return ENOMEM;
        }
        is_new_container = true;
    }

    /* Create task */
    task = create_task(container, current);
    if (!task) {
        ERROR("Unable to create task %d.\n", current->pid);
        mutex_unlock(&c_lock);
        return ENOMEM;
    }

    mutex_unlock(&c_lock);
    if (!is_new_container) {
        /* This is not the first task in the container, put it to sleep */
        DEBUG("Putting new task to sleep: %llu:%d\n", task->container->cid, task->pid);
        /* De-schedule new task */
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    }
    
    return 0;
}

/**
 * Free an object from memory container.
 * 
 * Finds a container based on the process id. If container is not found 
 * corresponding error is returned.
 * Frees an object that belongs to this container.
 * 
 * external functions needed:
 * copy_from_user(), mutex_lock(), mutex_unlock(), kfree()
 */
int memory_container_free(struct memory_container_cmd __user *user_cmd)
{
    struct container *container = NULL;
    struct object *object = NULL;
    struct memory_container_cmd cmd;

    DEBUG("Called free, pid:%d.\n", current->pid);

    /* Copy user data to kernel */
    if (copy_from_user(&cmd, (void *) user_cmd, sizeof(struct memory_container_cmd))) {
        ERROR("Copy from user of the user_cmd failure on PID: %d.\n", current->pid);
        return -EFAULT;
    }

    /* Find container with a given cid */
    container = get_container(cmd.cid);
    if (!container) {
        /* Could not find container in list - cannot remove the object */
        ERROR("Container does not exist, CID: %llu, unable to remove an object, OID: %llu.\n", cmd.cid, cmd.oid);
        return ENXIO;
    }
    
    DEBUG("Container is found, CID: %llu. Attempt to find object, OID: %%llu.\n", container->cid, cmd.oid);
    
    /* Find object with a given container and iod */
    object = get_object(container, cmd.oid);
    if (!object) {
        /* Could not find object in the list for a given container - cannot remove the object */
        ERROR("Unable to find object, OID: %llu in the container, CID: %llu; Will not remove object.\n", cmd.oid, container->cid);
        return ENXIO;
    }
    
    DEBUG("Object is found in the container, CID: %llu -> OID: %llu. Attempt to delete an object...\n", container->cid, object->oid);
    
    /* Delete the object from the container */
    list_del(&object->list);
    DEBUG("Deleted object in the container: CID: %llu -> OID: %llu. Freeing an object...\n", container->cid, object->oid);
    
    /* Free the object */
    kfree(object->shared_memory);
    kfree(object);
    
    /* If container does not have anymore tasks and objects in it, remove container */
    if (list_empty(&container->task_list) && list_empty(&container->object_list)) {
        list_del(&container->list);
        DEBUG("Container does not have anymore tasks nor objects. Deleted container from the list: %llu. Freeing container...\n", container->cid);
        kfree(container);
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
    DEBUG("CONTAINER: %llu\n", container->cid);
    /* Print container data */
    list_for_each_entry(task, &container->task_list, list) {
        debug_print_task(task);
    }
}

/**
 * Print debug information
 */
int memory_container_debug(struct memory_container_cmd __user *user_cmd)
{
    int locked = 0;
    struct container *container = NULL;

    /* Print mutex state and lock if possible - don't bother if someone is holding the lock */
    locked = mutex_trylock(&c_lock);
    if (!locked) {
        DEBUG("Unable to acquire mutex: %p\n", &c_lock);
    } else {
        DEBUG("Mutex acquired: %p\n", &c_lock);
    }

    /* Print container data */
    list_for_each_entry(container, &container_list, list) {
        debug_print_container(container);
    }

    /* Unlock if we successfully locked */
    if (locked) {
        mutex_unlock(&c_lock);
        DEBUG("Mutex released: %p\n", &c_lock);
    }
    return 0;
}

/**
 * control function that receive the command in user space and pass arguments to
 * corresponding functions.
 */
int memory_container_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg)
{
    switch (cmd)
    {
    case MCONTAINER_IOCTL_CREATE:
        return memory_container_create((void __user *)arg);
    case MCONTAINER_IOCTL_DELETE:
        return memory_container_delete((void __user *)arg);
    case MCONTAINER_IOCTL_LOCK:
        return memory_container_lock((void __user *)arg);
    case MCONTAINER_IOCTL_UNLOCK:
        return memory_container_unlock((void __user *)arg);
    case MCONTAINER_IOCTL_FREE:
        return memory_container_free((void __user *)arg);
    case PCONTAINER_IOCTL_DEBUG:
        return memory_container_debug((void __user *)arg);
    default:
        return -ENOTTY;
    }
}
