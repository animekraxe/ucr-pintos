#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "threads/malloc.h"

void halt (void);
void exit (int status);
int wait (pid_t pid);
pid_t exec (const char* cmd_line);

//Filesystem calls
bool create (const char* file, unsigned initial_size);
bool remove (const char* file);
int open (const char* file);
int filesize (int fd);
int read (int fd, void* buffer, unsigned length);
int write (int fd, const void* buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

//Filesystem bookkeeeping as recommended by:
//http://courses.cs.vt.edu/~cs3204/fall2009/pintos-vt-local/Project2Session.pdf

//1 global lock for filesystem access
struct lock file_lock;

//Info for file in thread file list
struct file_info { 
    int fd;
    struct file* file;
    struct list_elem felem;
};

//File helper functions
int process_file (const char* file);
struct file_info* get_file (int fd);
void close_file (int fd);
void close_all_files (struct thread* t);

static void syscall_handler (struct intr_frame *);

/* New functions */
int get_arg(struct intr_frame* f, int i);
void fill_args(struct intr_frame *f, int* args, int numArgs);
void test_bad_address(const void* addr);
void* kptr (const void* addr);

void
syscall_init (void) 
{
    lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
    test_bad_address(f->esp);

    //Arguments passed to syscall, can only have 3 at most
    int funcArgs[3]; 

    int* syscall_id = (int*)f->esp;
    switch (*syscall_id) {
        case SYS_EXIT:
        {
            //Sys_exit needs 1 argument
            fill_args(f, &funcArgs[0], 1); 
            exit(funcArgs[0]);
            break;
        }
        case SYS_WAIT:
        {
            fill_args(f, &funcArgs[0], 1);
            f->eax = wait(funcArgs[0]);
            break;
        }
        case SYS_HALT:
        {
            halt();
            break;
        }
        case SYS_WRITE:
        {
            fill_args(f, &funcArgs[0], 3);
            void* kp = kptr((const void*)funcArgs[1]);
            f->eax = write(funcArgs[0], (const char*)kp, (unsigned)funcArgs[2]);
            break;
        }
        case SYS_READ:
        {
            fill_args(f, &funcArgs[0], 3);
            void* kp = kptr((const void*)funcArgs[1]);
            f->eax = read(funcArgs[0], kp, (unsigned)funcArgs[2]);
            break;
        }
        case SYS_EXEC:
        {
            fill_args(f, &funcArgs[0], 1);
            void* kp = kptr((const void*)funcArgs[0]);
            f->eax = exec((const char*)kp);
            break;
        }
        case SYS_CREATE:
        {
            fill_args(f, &funcArgs[0], 2);
            void* kp = kptr((const void*)funcArgs[0]);
            f->eax = create((const char*)kp, (unsigned)funcArgs[1]);
            break;
        }
        case SYS_REMOVE:
        {
            fill_args(f, &funcArgs[0], 1);
            void* kp = kptr((const void*)funcArgs[0]);
            f->eax = remove((const char*)kp);
            break;
        }
        case SYS_OPEN:
        {
            fill_args(f, &funcArgs[0], 1);
            void* kp = kptr((const void*)funcArgs[0]);
            f->eax = open((const char*)kp);
            break;
        }
        case SYS_FILESIZE:
        {
            fill_args(f, &funcArgs[0], 1);
            f->eax = filesize(funcArgs[0]);
            break;
        }
        case SYS_SEEK:
        {
            fill_args(f, &funcArgs[0], 2);
            seek(funcArgs[0], (unsigned)funcArgs[1]);
            break;
        }
        case SYS_TELL:
        {
            fill_args(f, &funcArgs[0], 1);
            f->eax = tell(funcArgs[0]);
        }
        default:
            break; 
    }
}

void halt (void)
{
    shutdown_power_off();
}

void exit (int status)
{
    struct thread* current = thread_current();

    //Set return status
    if (get_thread(current->process->parent_tid)) {
        current->process->is_done = true;
        current->process->exit_status = status;
    }

    printf("%s: exit(%d)\n", current->name, status);
    thread_exit();
}

int wait (pid_t pid)
{
    return process_wait(pid);
}

pid_t exec (const char* cmd_line)
{
    pid_t pid = (pid_t)process_execute(cmd_line);
    if (pid == TID_ERROR)
        return -1;

    struct process* process = get_child(pid);
    while ((get_child(pid)) && get_child(pid)->load_state == LOAD_PENDING) 
    {
     //   barrier();
    }

    if (process->load_state != LOAD_SUCCESS)
        return -1;

    return pid;
}

int write (int fd, const void* buffer, unsigned size)
{
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        return size;
    }

    struct file_info* f = get_file(fd);
    if (!f) return -1;

    lock_acquire(&file_lock);
    int ret = file_write(f->file, buffer, size);
    lock_release(&file_lock);
    return ret;
}


int get_arg(struct intr_frame *f, int i)
{
    int* arg = (int*)f->esp + 1 + i;
    test_bad_address((const void*)arg);
    return *arg;
}

void fill_args(struct intr_frame *f, int* args, int numArgs)
{
    int i;
    for (i = 0; i < numArgs; ++i)
        args[i] = get_arg(f, i);
}

void test_bad_address (const void* addr)
{
    if (!is_user_vaddr(addr))
        exit(-1);

    kptr(addr);
}

void* kptr (const void* addr)
{
    if (!is_user_vaddr((const void*)addr))
        exit(-1);
    void* kptr = pagedir_get_page(thread_current()->pagedir, addr);
    if (!kptr)
        exit(-1);
    return kptr;
}

bool create (const char* file, unsigned initial_size)
{
    lock_acquire(&file_lock);
    bool ret = filesys_create(file, initial_size);
    lock_release(&file_lock);

    return ret;
}

bool remove (const char* file)
{
    lock_acquire(&file_lock);
    bool ret = filesys_remove(file);
    lock_release(&file_lock);

    return ret;
}

int read (int fd, void* buffer, unsigned size)
{
    if (fd == STDIN_FILENO) {
        unsigned i;
        uint8_t* buf = (uint8_t*)buffer;
        for (i = 0; i < size; ++i)
            buf[i] = input_getc();
        return size;
    }

    struct file_info* f = get_file(fd);
    if (!f) return -1;

    lock_acquire(&file_lock);
    int ret = file_read(f->file, buffer, size);
    lock_release(&file_lock);
    return ret;
}

int filesize (int fd)
{
    struct file_info* f = get_file(fd);
    if (!f) return -1;
    lock_acquire(&file_lock);
    int ret = file_length(f->file);
    lock_release(&file_lock);
    return ret;
}

void seek (int fd, unsigned position)
{
    struct file_info* f = get_file(fd);
    if (!f) return;
    lock_acquire(&file_lock);
    file_seek(f->file, position);
    lock_release(&file_lock);
}

unsigned tell (int fd)
{
    struct file_info* f = get_file(fd);
    if (!f) return -1;
    lock_acquire(&file_lock);
    unsigned ret = (unsigned)file_tell(f->file);
    lock_release(&file_lock);
    return ret;
}

int open (const char* file)
{
    lock_acquire(&file_lock);
    int ret = process_file(file);
    lock_release(&file_lock);

    return ret;
}

void close (int fd)
{
    lock_acquire(&file_lock);
    close_file(fd);
    lock_release(&file_lock);
}

void close_all_files (struct thread* t)
{
    struct list_elem* e = list_begin(&t->file_list);
    
    while (e != list_end(&t->file_list))
    {
        struct list_elem* next = e->next;
        struct file_info* f = list_entry(e, struct file_info, felem);
        close_file(f->fd);
        e = next;
    }
}

void close_file (int fd)
{
    struct file_info* f = get_file(fd);
    if (!f) {
        return;
    }
    list_remove(&f->felem);
    file_close(f->file);
    free(f);
}

int process_file (const char* filename)
{
    struct file* file = filesys_open(filename);
    if (!file) return -1;

    struct thread* current = thread_current();
    struct file_info* f = malloc(sizeof(struct file_info));
    f->file = file;
    f->fd = current->fd;
    ++current->fd;
    list_push_back(&current->file_list, &f->felem);

    return f->fd;
}

struct file_info* get_file (int fd)
{
    struct list_elem* e;
    struct thread* current = thread_current();

    for (e = list_begin(&current->file_list); e != list_end(&current->file_list);
         e = list_next(e))
    {
        struct file_info* f = list_entry(e, struct file_info, felem);
        if (f->fd == fd)
            return f;
    }
    return NULL;
}

//Cleanup files and children from process
void process_cleanup (struct thread* t)
{
    close_all_files(t);

    struct list_elem* e = list_begin(&t->child_list);
    while (e != list_end(&t->child_list))
    {
        struct list_elem* next = e->next;
        struct process* p = list_entry(e, struct process, cpelem);
        list_remove(&p->cpelem);
        free(p);
        e = next;
    }
}

