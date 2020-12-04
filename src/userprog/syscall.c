#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <list.h>
#include <stdbool.h>

#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "process.h"
#include "threads/vaddr.h" 
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "devices/input.h"


#include "../filesys/file.h"
#include "../filesys/filesys.h"
#include "../filesys/inode.h"
#include "../filesys/off_t.h"

static void syscall_handler (struct intr_frame *);

struct file {
	struct inode *inode;
	off_t pos;
	bool deny_write;
};

void
check_user_vaddr(const void *vaddr)
{
	if(!is_user_vaddr(vaddr))
		exit(-1);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	switch(*(uint32_t*)(f->esp)) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			check_user_vaddr(f->esp +4);
			exit(*(uint32_t*)(f->esp+4));
			break;
		case SYS_EXEC:
			check_user_vaddr(f->esp + 4);
			f->eax = exec((const char*)*(uint32_t*)(f->esp+4));
			break;
		case SYS_WAIT:
			check_user_vaddr(f->esp+4);
			f->eax = wait(*(uint32_t*)(f->esp+4));
			break;
		case SYS_CREATE:
			check_user_vaddr(f->esp + 4);
			check_user_vaddr(f->esp + 8);
			f->eax = create((const char*)*(uint32_t*)(f->esp + 4),
					(unsigned)*(uint32_t*)(f->esp + 8));
			break;
		case SYS_REMOVE:
			check_user_vaddr(f->esp + 4);
			f->eax = remove((const char*)*(uint32_t*)(f->esp + 4));
			break;
		case SYS_OPEN:
			check_user_vaddr(f->esp + 4);
			f->eax = open((const char*)*(uint32_t*)(f->esp + 4));
			break;
		case SYS_FILESIZE:
			check_user_vaddr(f->esp + 4);
			f->eax = filesize((int)*(uint32_t*)(f->esp+4));
			break;
		case SYS_READ:
			check_user_vaddr(f->esp + 4);
			check_user_vaddr(f->esp + 8);
			check_user_vaddr(f->esp + 12);
			f->eax = read((int)*(uint32_t*)(f->esp + 4),
					(void*)*(uint32_t*)(f->esp + 8),
					(unsigned)*((uint32_t*)(f->esp + 12)));
			break;
		case SYS_WRITE:
			f->eax = write((int)*(uint32_t*)(f->esp+4),
					(void*)*(uint32_t*)(f->esp+8),
					(unsigned)*((uint32_t*)(f->esp+12)));
			break;
		case SYS_SEEK:
			check_user_vaddr(f->esp + 4);
			check_user_vaddr(f->esp + 8);
			seek((int)*(uint32_t*)(f->esp + 4), 
					(unsigned)*(uint32_t*)(f->esp + 8));
			break;
		case SYS_TELL:
			check_user_vaddr(f->esp + 4);
			f->eax = tell((int)*(uint32_t*)(f->esp + 4));
			break;
		case SYS_CLOSE:
			check_user_vaddr(f->esp + 4);
			close((int)*(uint32_t*)(f->esp + 4));
			break;
	}

  //thread_exit ();
}

void
halt(void)
{
	shutdown_power_off();
}

void
exit(int status)
{
	int i;

	printf("%s: exit(%d)\n", thread_name(), status);
	thread_current()->exit_status = status;
	for (i = 3; i < 128; i++) {
		if (thread_current()->fd[i] != NULL)
			close(i);
	}
	thread_exit();
}

pid_t
exec(const char *cmd_line)
{
	return process_execute(cmd_line);
}

int
wait(pid_t pid)
{
	return process_wait(pid);
}

bool
create(const char *file, unsigned initial_size)
{
	if (file == NULL)
		exit(-1);
	check_user_vaddr(file);
	return filesys_create(file, initial_size);
}

bool
remove(const char *file)
{
	if (file == NULL)
		exit(-1);
	check_user_vaddr(file);
	return filesys_remove(file);
}

int
open(const char *file)
{
	int i;
	struct file *fp;

	if (file == NULL)
		exit(-1);
	check_user_vaddr(file);
	fp = filesys_open(file);
	if (fp == NULL)
		return -1;
	else {
		for (i = 3; i < 128; i++) {
			if (thread_current()->fd[i] == NULL) {
				if (strcmp(thread_current()->name, file) == 0)
					file_deny_write(fp);
				thread_current()->fd[i] = fp;
				return i;
			}
		}
	}
	return -1;
}

int
filesize(int fd)
{
	if(thread_current()->fd[fd] == NULL)
		exit(-1);
	return file_length(thread_current()->fd[fd]);
}

int
read(int fd, void *buffer, unsigned size)
{
	int i;
	check_user_vaddr(buffer);
	if (fd == 0) {
		for (i = 0; i < size; i++) {
			if (((char*)buffer)[i] == '\0')
				break;
		}
	}
	else if (fd > 2) {
		if (thread_current()->fd[fd] == NULL)
			exit(-1);
		return file_read(thread_current()->fd[fd], buffer, size);
	}
	return i;
}

int
write(int fd, const void *buffer, unsigned size)
{
	check_user_vaddr(buffer);
	if(fd == 1) {
		putbuf(buffer, size);
		return size;
	}
	else if (fd > 2) {
		if (thread_current()->fd[fd] == NULL) {
			exit(-1);
		}
		if (thread_current()->fd[fd]->deny_write)
			file_deny_write(thread_current()->fd[fd]);
		return file_write(thread_current()->fd[fd], buffer, size);
	}
	return -1;
}

void
seek(int fd, unsigned position)
{
	if (thread_current()->fd[fd] == NULL)
		exit(-1);
	file_seek(thread_current()->fd[fd], position);
}

unsigned
tell(int fd)
{
	if (thread_current()->fd[fd] == NULL)
		exit(-1);
	return file_tell(thread_current()->fd[fd]);
}

void
close(int fd)
{
	struct thread *cur = thread_current();
	struct list *file_lst = &(cur->file_list);
	struct file_nth *fp = NULL;
	struct list_elem *e = NULL;

	if (thread_current()->fd[fd] == NULL)
		exit(-1);

	for (e = list_begin(file_lst);
			e != list_end(file_lst);
			e = list_next(e)) {

		fp = list_entry(e, struct file_nth, file_elem);

		if(fp->fd == fd) {
			if(fp->fd == NULL)
				exit(-1);
			file_close(fp->f);
			list_remove(e);

			if(fp == NULL);
			else
				free(fp);
			break;
		}
	}

}


