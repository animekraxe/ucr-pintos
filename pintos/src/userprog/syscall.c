#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"

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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{

    int* syscall_id = (int*)f->esp;

    switch (*syscall_id) {
        case SYS_EXIT:
            break;
        case SYS_WAIT:
            break;
        case SYS_HALT:
            halt();
            break;
        case SYS_WRITE:
            break;
        default:
            break; 
    }



  printf ("system call!\n");
  thread_exit ();
}

void halt (void)
{
    shutdown_power_off();
}

void exit_handler (struct intr_frame * f)
{
    int* pid = (int*)(f->esp - 4);
    pagedir_ge
   
}

void exit (int status)
{
    struct thread* current = thread_current();
    printf("%s exit %d", current->name, status);
    thread_exit();
}

int wait (pid_t pid)
{
}
