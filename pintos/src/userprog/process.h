#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <user/syscall.h>

enum load_status
{
	LOAD_PENDING,
	LOAD_SUCCESS,
	LOAD_FAILURE
};

//Process Bookkeeping
struct process {
    pid_t pid;
    tid_t parent_tid;
    bool already_waiting;
    enum load_status load_state;
    bool is_done;
    int exit_status;
    int fd; 
    struct list_elem cpelem; //List element for child_list in parent thread
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
