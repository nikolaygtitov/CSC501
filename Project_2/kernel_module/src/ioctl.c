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

#define PCONTAINER_IOCTL_DEBUG _IOWR('N', 0x50, struct memory_container_cmd)
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
    unsigned long size;
    unsigned long pfn;
    struct mutex lock;
    struct list_head list;
};

struct mutex c_lock;
struct list_head container_list;


/**
 * Get the container with the given cid.
 *
 * Iterates through all of the existing containers and tries to find container
 * based on the given container id.
 * If the container does not exist, returns NULL.
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
 * Get the running task for a given pid of the process.
 *
 * Iterates through all containers and all the tasks within each container to
 * find a task.
 * If the task does not exist, returns NULL.
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
 *
 * Iterates through all containers and all the objects within each container to
 * find an object.
 * If the object does not exist, returns NULL.
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
 *
 * Allocates container and assigns container id to the cid.
 * Initializes container list head and task list head.
 * Adds container to list.
 * If allocation of memory for container fails, returns NULL.
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
 *
 * Allocates task and sets task fields.
 * Initializes task list head and adds newly create task next to the currently
 * running task of the task list of the container.
 * If allocation of memory for task fails, returns NULL.
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

    /* Add this new task next to the currently running task of the task list of the container */
    list_add(&task->list, container->task_list.next);

    DEBUG("Added task %llu:%d\n", container->cid, task->pid);

    return task;
}

/**
 * Create a VMM area memory object.
 *
 * Allocates object and assigns the object id.
 * Initializes mutex lock and object list head.
 * Inserts the object into VMM area memory list of the resource memory
 * container.
 * If allocation of memory for object fails, returns NULL.
 */
static struct object * create_object(struct container *container, struct vm_area_struct *vma)
{
    struct object *object = NULL;

    /* Allocate object */
    object = (struct object *) kcalloc(1, sizeof(struct object), GFP_KERNEL);
    if (!object) {
        return NULL;
    }

    /* Set object fields */
    object->oid = vma->vm_pgoff;

    mutex_init(&object->lock);
    
    /* Initialize object list head */
    INIT_LIST_HEAD(&object->list);

    /* Add this new object to the end of the list of objects */
    list_add_tail(&object->list, &container->object_list);
    
    DEBUG("Added object OID: %llu into container CID: %llu.\n", object->oid, container->cid);

    return object;
}

/**
 * Set object fields.
 *
 * Allocates shared memory. Sets all of the objects fields based on the given
 * VMM memory area.
 * Maps virtual address to a physical.
 * If allocation of shared memory fails, returns NULL.
 */
static struct object * set_object_fields(struct object *object, struct vm_area_struct *vma)
{
    /* Allocate requested size of the memory for object */
    object->size = (unsigned long) (vma->vm_end - vma->vm_start);
    object->shared_memory = kzalloc(object->size, GFP_KERNEL);
    if (!object->shared_memory) {
        return NULL;
    }
    /* Map virtual address to physical */
    object->pfn = virt_to_phys((void *) object->shared_memory)>>PAGE_SHIFT;
    return object;
}

/* Delete an object from the container and free it.
 *
 * Deletes from the container and frees an object.
 * If corresponding container does not have anymore tasks and objects, removes
 * and frees the container.
 */
static void delete_object(struct container *container, struct object *object)
{
    DEBUG("Deleting and freeing an object: CID: %llu -> OID: %llu.\n", container->cid, object->oid);
    list_del(&object->list);
    /* Free the object */
    kfree(object);
    /* If container does not have anymore tasks and objects in it, remove container */
    if (list_empty(&container->task_list) && list_empty(&container->object_list)) {
        DEBUG("Container does not have anymore tasks and objects: %llu. Attempt to deleted and free a container...\n", container->cid);
        list_del(&container->list);
        /* Free container */
        kfree(container);
    }
    return;
}

/*
 * Request to remap kernel space memory into the user-space memory.
 *
 * The kernel module takes an offset from the user-space library as vm area
 * struct and allocates shared memory with the size associated with the offset.
 * The offset is considered to be an object id (oid). If an object associated
 * with an offset was already created/requested since the kernel module is
 * loaded, the mmap request should assign the address of the previously
 * allocated object to the mmap request.
 * Finds a task based on pid by iterating through all containers and all the
 * tasks within each container. If the task is not found returns corresponding
 * error.
 * Finds an object based on the found task, its corresponding container, and
 * given object id. If object is not found, it has not been created yet.
 * Creates an object based on the given VMM memory area struct and sets all
 * the object fields with the given VMM memory area struct attributes.
 * Object fields are only set if there is no shared memory allocated for the
 * found object or this is a new object.
 * Lastly, remaps kernel memory into the user-space.
 */
int memory_container_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct task *task = NULL;
    struct object *object = NULL;
    //struct vm_area_struct kernel_vma;

    DEBUG("Called mmap, pid:%d.\n", current->pid);

    /* Copy user data to kernel */
/*
    if (copy_from_user(&kernel_vma, (void *) vma, sizeof(struct vm_area_struct))) {
        ERROR("Copy from user of the vma failure on PID: %d.\n", current->pid);
        return -EFAULT;
    }
*/

    mutex_lock(&c_lock);
    DEBUG("Locked: %s\n", "c_lock");
    task = get_task(current->pid);
    if (!task) {
        ERROR("No such running task with PID: %d is found in existing containers.\n", current->pid);
        mutex_unlock(&c_lock);
        return ESRCH;
    }
    DEBUG("Found task: %d\n", current->pid);
    
    /* Find an object for a given container and object id */
    object = get_object(task->container, vma->vm_pgoff);
    
    if (!object) {
        /* Could not find object in the given container - create new object */
        DEBUG("No such object OID: %lu in the container CID: %llu. Attempt to create new object...\n", vma->vm_pgoff, task->container->cid);
        object = create_object(task->container, vma);
        if (!object) {
            ERROR("Unable to create object OID: %lu in the container CID: %llu -> PID: %d due to memory allocation issues.\n", vma->vm_pgoff, task->container->cid, task->pid);
            mutex_unlock(&c_lock);
            return ENOMEM;
        }
    }
    DEBUG("Found object: %llu\n", object->oid);

    if (!object->shared_memory) {
        /* Shared memory for the object is not allocated yet even though object is created */
        DEBUG("Object shared memory is not alloc yet: %llu\n", object->oid);
        /* Set object fields */
        object = set_object_fields(object, vma);
        if (!object) {
            ERROR("Unable to set object fields of object OID: %lu in the container CID: %llu -> PID: %d due to memory allocation issues.\n", vma->vm_pgoff, task->container->cid, task->pid);
            mutex_unlock(&c_lock);
            return ENOMEM;
        }
        DEBUG("Object fields are set: %llu\n", object->oid);
    }
    DEBUG("Ready to call remap_pfn_range(): %llu\n", object->oid);
    
    /* Remap kernel memory into the user-space */
    if (remap_pfn_range(vma, vma->vm_start, object->pfn, object->size, vma->vm_page_prot) != 0) {
        ERROR("Failed: Unable to remap kernel memory into the user space; CID: %llu -> PID: %d -> OID: %llu.\n", task->container->cid, task->pid, object->oid);
        mutex_unlock(&c_lock);
        return EADDRNOTAVAIL;
    }
    
    DEBUG("Success: Request to remap kernel space memory into the user-space memory; CID: %llu -> PID: %d -> OID: %llu.\n", task->container->cid, task->pid, object->oid);
    mutex_unlock(&c_lock);
    return 0;
}

/*
 * Mutex Lock.
 *
 * Finds a task based on pid by iterating through all containers and all the
 * tasks within each container. If the task is not found returns corresponding
 * error.
 * Finds an object based on the found task, its corresponding container, and
 * given object id. If object is not found, it has not been created yet.
 * Creates an object by creating a dummy VMM memory area struct and assigning
 * its offset to the object id. After object is created free dummy VMM memory
 * area. Object is only created if it does not exist.
 * Locks the object.
 */
int memory_container_lock(struct memory_container_cmd __user *user_cmd)
{
    struct task *task = NULL;
    struct object *object = NULL;
    struct vm_area_struct *vma = NULL;
    struct memory_container_cmd cmd;

    /* Copy user data to kernel */
    if (copy_from_user(&cmd, (void *) user_cmd, sizeof(struct memory_container_cmd))) {
        ERROR("Copy from user of the cmd on PID: %d.\n", current->pid);
        return -EFAULT;
    }

    DEBUG("Called lock, OID: %llu\n", cmd.oid);
    
    mutex_lock(&c_lock);
    
    /* Get task based on the process id */
    task = get_task(current->pid);
    if (!task) {
        ERROR("No such running task with PID: %d is found in existing containers.\n", current->pid);
        mutex_unlock(&c_lock);
        return ESRCH;
    }
    
    /* Find an object for a given container and object id */
    object = get_object(task->container, cmd.oid);
    
    if (!object) {
        /* There is no such object with oid, create one */
        DEBUG("No such object OID: %llu in the container CID: %llu. Attempt to create an object ...\n", cmd.oid, task->container->cid);
        
        /* Allocate dummy vma just for initial creation of object */
        vma = (struct vm_area_struct *) kcalloc(1, sizeof(struct vm_area_struct), GFP_KERNEL);
        if (!vma) {
            ERROR("Unable to create dummy VMM memory area struct for creating new object OID: %llu due to memory allocation issues.\n", cmd.oid);
            mutex_unlock(&c_lock);
            return ENOMEM;
        }
        vma->vm_pgoff = cmd.oid;
        
        /* Create new object */
        object = create_object(task->container, vma);
        if (!object) {
            ERROR("Unable to create object OID: %lu in the container CID: %llu -> PID: %d due to memory allocation issues.\n", vma->vm_pgoff, task->container->cid, task->pid);
            mutex_unlock(&c_lock);
            return ENOMEM;
        }
        
        /* Free dummy vma */
        kfree(vma);
    }

    mutex_lock(&object->lock);
    mutex_unlock(&c_lock);
    return 0;
}

/*
 * Mutex Unlock.
 *
 * Finds a task based on pid by iterating through all containers and all the
 * tasks within each container. If the task is not found, returns
 * corresponding error.
 * Finds an object based on the current task, its corresponding container, and
 * given object id. If the object is not found returns corresponding error.
 * Unlocks the object.
 * Checks whether shared memory of the object is freed, then there was an
 * attempt to delete this object, but the object was locked and delete was
 * unsuccessful.
 * Deletes this object from the container and frees it if its shared memory is
 * freed. If corresponding container does not have anymore tasks and objects,
 * removes the container.
 */
int memory_container_unlock(struct memory_container_cmd __user *user_cmd)
{
    struct task *task = NULL;
    struct object *object = NULL;
    struct memory_container_cmd cmd;

    /* Copy user data to kernel */
    if (copy_from_user(&cmd, (void *) user_cmd, sizeof(struct memory_container_cmd))) {
        ERROR("Copy from user of the cmd on PID: %d.\n", current->pid);
        return -EFAULT;
    }

    DEBUG("Called unlock, oid:%llu\n", cmd.oid);
    
    mutex_lock(&c_lock);
    task = get_task(current->pid);
    if (!task) {
        ERROR("No such running task with PID: %d is found in existing containers.\n", current->pid);
        mutex_unlock(&c_lock);
        return ESRCH;
    }

    /* Find an object for a given container and object id */
    object = get_object(task->container, cmd.oid);
    
    if (!object) {
        ERROR("No such object OID: %llu in the container CID: %llu.\n", cmd.oid, task->container->cid);
        mutex_unlock(&c_lock);
        return ESRCH;
    }
    
    mutex_unlock(&object->lock);
    
    /* Delete the object from the container if it was attempted to be deleted */
    if (!object->shared_memory) {
        DEBUG("Shared memory of the object is freed: CID: %llu -> OID: %llu. Attempt to delete and free an object...\n", task->container->cid, object->oid);
        delete_object(task->container, object);
    }
    
    mutex_unlock(&c_lock);
    return 0;
}

/**
 * Delete the task from the container.
 *
 * Finds a task based on pid by iterating through all containers and all the
 * tasks within each container. If the task is not found, returns corresponding
 * error.
 * Deletes the task from the container.
 * Deletes and frees container only if container does not have anymore tasks and
 * objects in it.
 */
int memory_container_delete(struct memory_container_cmd __user *user_cmd)
{
    struct task *task = NULL;

    DEBUG("Called delete: pid:%d\n", current->pid);

    mutex_lock(&c_lock);
    /* Find a task based on pid */
    task = get_task(current->pid);
    if (!task) {
        ERROR("No such running task with PID: %d is found in existing containers.\n", current->pid);
        mutex_unlock(&c_lock);
        return ESRCH;
    }

    /* Delete the task from the container */
    list_del(&task->list);
    DEBUG("Deleted task: CID: %llu -> PID: %d. Attempt to free task...\n", task->container->cid, task->pid);
    
    /* If container does not have anymore tasks and objects in it, remove container */
    if (list_empty(&task->container->task_list) && list_empty(&task->container->object_list)) {
        DEBUG("Container does not have anymore tasks and objects: %llu. Attempt to deleted and free a container...\n", task->container->cid);
        list_del(&task->container->list);
        /* Free container */
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
 * Checks if container already exists. If it does not exist, creates new
 * container.
 * Creates new task. Inserts new task into the task list of the container.
 */
int memory_container_create(struct memory_container_cmd __user *user_cmd)
{
    struct container *container = NULL;
    struct task *task = NULL;
    struct memory_container_cmd cmd;

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
    }

    /* Create task */
    task = create_task(container, current);
    if (!task) {
        ERROR("Unable to create task %d.\n", current->pid);
        mutex_unlock(&c_lock);
        return ENOMEM;
    }

    mutex_unlock(&c_lock);
    
    return 0;
}

/**
 * Free an object from memory container.
 *
 * Finds a task based on pid by iterating through all containers and all the
 * tasks within each container. If the task is not found returns corresponding
 * error.
 * Finds an object based on the current task, its corresponding container, and
 * given object id. If the object is not found returns corresponding error.
 * Frees shared memory of the object, but does not delete the object yet since
 * it can be locked.
 * Checks whether an object is locked, then does not delete it from the
 * container and does not free it.
 * memory_container_unlock() function will complete deletion of the object when
 * it is unlocked.
 * Otherwise, deletes this object from the container and frees it.
 * If corresponding container does not have anymore tasks and objects, removes
 * the container.
 */
int memory_container_free(struct memory_container_cmd __user *user_cmd)
{
    struct task *task = NULL;
    struct object *object = NULL;
    struct memory_container_cmd cmd;

    DEBUG("Called free, pid:%d.\n", current->pid);

    /* Copy user data to kernel */
    if (copy_from_user(&cmd, (void *) user_cmd, sizeof(struct memory_container_cmd))) {
        ERROR("Copy from user of the user_cmd failure on PID: %d.\n", current->pid);
        return -EFAULT;
    }

    mutex_lock(&c_lock);

    /* Get task based on the process id */
    task = get_task(current->pid);
    if (!task) {
        ERROR("No such running task with PID: %d is found in existing containers.\n", current->pid);
        mutex_unlock(&c_lock);
        return ESRCH;
    }

    /* Find an object for a given container and object id */
    object = get_object(task->container, cmd.oid);

    if (!object) {
        /* Could not find object in the list for a given container - cannot remove the object */
        ERROR("Unable to find object, OID: %llu in the container, CID: %llu; Will not remove object.\n", cmd.oid, task->container->cid);
        mutex_unlock(&c_lock);
        return ENXIO;
    }
    
    DEBUG("Object is found in the container, CID: %llu -> OID: %llu. Attempt to free it shared memory...\n", task->container->cid, object->oid);
    
    /* Free shared memory, but do not delete the object, since it can be locked */
    kfree(object->shared_memory);
    object->shared_memory = NULL;
    
    /* Check if object is locked, otherwise delete and free the object from the container */
    if (!mutex_is_locked(&object->lock)) {
        DEBUG("Object is not locked: CID: %llu -> OID: %llu. Attempt to delete and free an object ...\n", task->container->cid, object->oid);
        delete_object(task->container, object);
    }
    
    mutex_unlock(&c_lock);
    return 0;
}

/*
 * Print content of the task for debugging purposes.
 */
static void debug_print_task(struct task *task)
{
    if (!task) {
        DEBUG("  NULL%s\n", "");
    } else {
        DEBUG("  TASK: %d\n", task->pid);
        DEBUG("    State: %d\n", (int)task->task_struct->state);
    }
}

/*
 * Print content of the container for debugging purposes.
 */
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
 * Print debug information.
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
