#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

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

static void syscall_handler (struct intr_frame *);

int getArg(struct intr_frame* f, int i);
void fillArgs(struct intr_frame *f, int* args, int numArgs);

int getArg(struct intr_frame *f, int i)
{
    int* arg = (int*)f->esp + 1 + i;
    if (!is_user_vaddr((void*)arg)) { //That's not a user address...
        exit(-1);
    }
    return *arg;
}

void fillArgs(struct intr_frame *f, int* args, int numArgs)
{
    int i;
    for (i = 0; i < numArgs; ++i)
        args[i] = getArg(f, i);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
    //Arguments passed to syscall, can only have 3 at most
    int funcArgs[3]; 

    int* syscall_id = (int*)f->esp;

    switch (*syscall_id) {
        case SYS_EXIT:
        {
            //Sys_exit needs 1 argument
            fillArgs(f, &funcArgs[0], 1); 
            exit(funcArgs[0]);
            break;
        }
        case SYS_WAIT:
        {
            fillArgs(f, &funcArgs[0], 1);
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
            //write needs 3 args
            fillArgs(f, &funcArgs[0], 3);
            void* kptr = pagedir_get_page(thread_current()->pagedir, (const void*)funcArgs[1]);
            if (!kptr)
                exit(-1);
            f->eax = write(funcArgs[0], (const void*)kptr, (unsigned)funcArgs[2]);
            break;
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
    printf("%s: exit(%d)\n", current->name, status);
    thread_exit();
}

int wait (pid_t pid)
{
    return process_wait(pid);
}

int write (int fd, const void* buffer, unsigned size)
{
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }
}
