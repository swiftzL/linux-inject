#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>
#include <dlfcn.h>
#include "utils.h"
#include "ptrace.h"
#include <sys/ptrace.h>

/*
 * injectSharedLibrary()
 *
 *
 * 0000000000001d80 <injectSharedLibrary>:
	1d80:       55                      push   %rbp
	1d81:       48 89 e5                mov    %rsp,%rbp
	1d84:       48 89 7d f8             mov    %rdi,-0x8(%rbp)
	1d88:       48 89 75 f0             mov    %rsi,-0x10(%rbp)
	1d8c:       48 89 55 e8             mov    %rdx,-0x18(%rbp)
	1d90:       56                      push   %rsi
	1d91:       52                      push   %rdx
	1d92:       41 51                   push   %r9
	1d94:       49 89 f9                mov    %rdi,%r9
	1d97:       48 89 cf                mov    %rcx,%rdi
	1d9a:       41 ff d1                call   *%r9
	1d9d:       41 59                   pop    %r9
	1d9f:       cc                      int3
	1da0:       5a                      pop    %rdx
	1da1:       41 51                   push   %r9
	1da3:       49 89 d1                mov    %rdx,%r9
	1da6:       48 89 c7                mov    %rax,%rdi
	1da9:       48 be 01 00 00 00 00    movabs $0x1,%rsi
	1db0:       00 00 00
	1db3:       41 ff d1                call   *%r9
	1db6:       41 59                   pop    %r9
	1db8:       cc                      int3
	1db9:       48 89 c7                mov    %rax,%rdi
	1dbc:       5e                      pop    %rsi
	1dbd:       53                      push   %rbx
	1dbe:       48 89 f3                mov    %rsi,%rbx
	1dc1:       48 31 f6                xor    %rsi,%rsi
	1dc4:       cc                      int3
	1dc5:       ff d3                   call   *%rbx
	1dc7:       5b                      pop    %rbx
	1dc8:       5d                      pop    %rbp
	1dc9:       c3                      ret
	1dca:       66 0f 1f 44 00 00       nopw   0x0(%rax,%rax,1)

0000000000001dd0 <injectSharedLibrary_end>:
	1dd0:       55                      push   %rbp
	1dd1:       48 89 e5                mov    %rsp,%rbp
	1dd4:       5d                      pop    %rbp
	1dd5:       c3                      ret
	1dd6:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
	1ddd:       00 00 00


		regs.rdi = targetMallocAddr;
	regs.rsi = targetFreeAddr;
	regs.rdx = targetDlopenAddr;
	regs.rcx = libPathLength;
 */

void injectSharedLibrary()
{
	asm(
		"push %rsp \n"
		"push %rsi \n"
		"push %rdx");
		//malloc
	asm(
		"push %r9 \n"
		"mov %rdi,%r9 \n"
		"mov $50,%rdi \n"
		"callq *%r9 \n"
		"pop %r9 \n"
		"int $3");
		//dlopen
	asm(
		"pop %rdx \n"  //dlopen addr
		"push %r9 \n"  //
		"mov %rdx,%r9 \n"
		"mov %rax,%rdi \n"//so addr
		"xor %rsi,%rsi \n" //load_mod
		"mov $0x1,%esi \n"
		"callq *%r9 \n"
		"pop %r9 \n"
		"int $3 \n"
		);

	//------------------free 
	asm(
		// at this point, rax should still contain our malloc()d buffer from earlier.
		// we're going to free it, so move rax into rdi to make it the first argument to free().
		"mov %rax,%rdi \n"
		// pop rsi so that we can get the address to free(), which we pushed onto the stack a while ago.
		"pop %rsi \n"
		// save previous rbx value
		"push %rbx \n"
		// load the address of free() into rbx
		"mov %rsi,%rbx \n"
		// zero out rsi, because free() might think that it contains something that should be freed
		"xor %rsi,%rsi \n"
		// break in so that we can check out the arguments right before making the call
		"int $3 \n"
		// call free()
		"callq *%rbx \n"
		// restore previous rbx value
		"pop %rbx \n"
		"add %rsp,8");
}

/*
 * injectSharedLibrary_end()
 *
 * This function's only purpose is to be contiguous to injectSharedLibrary(),
 * so that we can use its address to more precisely figure out how long
 * injectSharedLibrary() is.
 *
 */

void dump_str(char *str)
{
	for (int i = 0; i < 100; i++)
	{
		printf("str %p %c ", *(str + i), *(str + i));
	}
}

void ptrace_dump_memeory(pid_t pid,u_int64_t address,int size) {
	char* newcode = malloc(size);
	ptrace_read(pid, address, newcode, size);
	for (int i = 0; i < size; i++)
	{
		printf("%02x", *((__u_char *)(newcode) + i));
	}

}

void injectSharedLibrary_end()
{
}

int main(int argc, char **argv)
{
	void* ssptr = dlopen("/root/linux-inject/sample-library.so",2);
	printf("ss ptr is %p \n",ssptr);
	printf("dlopen address is %p\n",dlopen);

	if (argc < 4)
	{
		usage(argv[0]);
		return 1;
	}

	char *command = argv[1];
	char *commandArg = argv[2];
	char *libname = argv[3];
	char *libPath = realpath(libname, NULL);

	char *processName = NULL;
	pid_t target = 0;

	if (!libPath)
	{
		fprintf(stderr, "can't find file \"%s\"\n", libname);
		return 1;
	}

	if (!strcmp(command, "-n"))
	{
		processName = commandArg;
		target = findProcessByName(processName);
		if (target == -1)
		{
			fprintf(stderr, "doesn't look like a process named \"%s\" is running right now\n", processName);
			return 1;
		}

		printf("targeting process \"%s\" with pid %d\n", processName, target);
	}
	else if (!strcmp(command, "-p"))
	{
		target = atoi(commandArg);
		printf("targeting process with pid %d\n", target);
	}
	else
	{
		usage(argv[0]);
		return 1;
	}

	int libPathLength = 50;

	int mypid = getpid();
	long mylibcaddr = getlibcaddr(mypid);

	// find the addresses of the syscalls that we'd like to use inside the
	// target, as loaded inside THIS process (i.e. NOT the target process)
	long mallocAddr = getFunctionAddress("malloc");
	long freeAddr = getFunctionAddress("free");
	long dlopenAddr = getFunctionAddress("dlopen");
	printf("self load addr is %p,", dlopenAddr);

	// use the base address of libc to calculate offsets for the syscalls
	// we want to use
	long mallocOffset = mallocAddr - mylibcaddr;
	long freeOffset = freeAddr - mylibcaddr;
	long dlopenOffset = dlopenAddr - mylibcaddr;

	// get the target process' libc address and use it to find the
	// addresses of the syscalls we want to use inside the target process
	long targetLibcAddr = getlibcaddr(target);
	printf("target libc addr %p\n", targetLibcAddr);
	long targetMallocAddr = targetLibcAddr + mallocOffset;
	long targetFreeAddr = targetLibcAddr + freeOffset;
	long targetDlopenAddr = targetLibcAddr + dlopenOffset;
	printf("target dl ope is %p offset is %p targetLibcAddr is %p \n", targetDlopenAddr, dlopenOffset, targetLibcAddr);
	// 0xffffffffff600000
	//           0xa00000
	struct user_regs_struct oldregs, regs;
	memset(&oldregs, 0, sizeof(struct user_regs_struct));
	memset(&regs, 0, sizeof(struct user_regs_struct));

	ptrace_attach(target);

	ptrace_getregs(target, &oldregs);
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

	// find a good address to copy code to
	long findaddr = freespaceaddr(target);
	long addr = findaddr + sizeof(long);
	printf("findaddr is %x final addr is %x\n", findaddr, addr);

	// now that we have an address to copy code to, set the target's rip to
	// it. we have to advance by 2 bytes here because rip gets incremented
	// by the size of the current instruction, and the instruction at the
	// start of the function to inject always happens to be 2 bytes long.
	regs.rip = addr + 2;

	// pass arguments to my function injectSharedLibrary() by loading them
	// into the right registers. note that this will definitely only work
	// on x64, because it relies on the x64 calling convention, in which
	// arguments are passed via registers rdi, rsi, rdx, rcx, r8, and r9.
	// see comments in injectSharedLibrary() for more details.
	regs.rdi = targetMallocAddr;
	regs.rsi = targetFreeAddr;
	regs.rdx = targetDlopenAddr;
	regs.rcx = libPathLength;
	// pring args
	printf("regs.rdi %p \n", regs.rdi);
	printf("regs.rsi %p \n", regs.rsi);
	printf("regs.rdx %p \n", regs.rdx);
	printf("regs.rcx %p \n", regs.rcx);

	ptrace_setregs(target, &regs);

	// figure out the size of injectSharedLibrary() so we know how big of a buffer to allocate.
	size_t injectSharedLibrary_size = (intptr_t)injectSharedLibrary_end - (intptr_t)injectSharedLibrary;
	printf("inject so library size is %d\n", injectSharedLibrary_size);

	intptr_t injectSharedLibrary_ret = (intptr_t)findRet(injectSharedLibrary_end) - (intptr_t)injectSharedLibrary;
	printf("inject sharedlibrary ret is %d\n", injectSharedLibrary_ret);

	// back up whatever data used to be at the address we want to modify.
	char *backup = malloc(injectSharedLibrary_size * sizeof(char));
	ptrace_read(target, addr, backup, injectSharedLibrary_size); // 备份指令 addr map中找一个x权限的内存地址

	// set up a buffer to hold the code we're going to inject into the
	// target process.
	char *newcode = malloc(injectSharedLibrary_size * sizeof(char));
	memset(newcode, 0, injectSharedLibrary_size * sizeof(char)); // 0x50

	// copy the code of injectSharedLibrary() to a buffer.
	memcpy(newcode, injectSharedLibrary, injectSharedLibrary_size);

	// overwrite the RET instruction with an INT 3.
	newcode[injectSharedLibrary_ret] = INTEL_INT3_INSTRUCTION; // ret -> int3

	// copy injectSharedLibrary()'s code to the target address inside the
	// target process' address space.
	ptrace_write(target, addr, newcode, injectSharedLibrary_size); // 0x50

	// now that the new code is in place, let the target run our injected
	// code.
	// dump the code
	for (int i = 0; i < 0x50; i++)
	{
		printf("%02x", *((__u_char *)(newcode) + i));
	}
	printf("\n");
	printf("ptrace cont 1\n");
	ptrace_cont(target); // runing

	//--------------------------------malloc stop

	// at this point, the target should have run malloc(). check its return
	// value to see if it succeeded, and bail out cleanly if it didn't.
	struct user_regs_struct malloc_regs;
	memset(&malloc_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &malloc_regs);
	unsigned long long targetBuf = malloc_regs.rax;
	if (targetBuf == 0)
	{
		fprintf(stderr, "malloc() failed to allocate memory\n");
		restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}
	printf("lib path addr is %p", targetBuf);

	printf("start call dlopen --%s--\n", libPath);
	ptrace_write(target, targetBuf, "/root/linux-inject/sample-library.so", strlen("/root/linux-inject/sample-library.so") + 1);
	// continue the target's execution again in order to call
	// __libc_dlopen_mode.
	printf("ptrace cont 2\n");
	//-----------------------------------dlopen start
//   ptrace(PTRACE_CONT, target, NULL, SIGSTOP);
// 	if(1) {
// 		exit(0);
// 	}
	//dump rip
	ptrace_dump_memeory(target,malloc_regs.rip,0x50);
	// ptrace_step(target);
	ptrace_cont(target);



	// as a courtesy, free the buffer that we allocated inside the target
	// process. we don't really care whether this succeeds, so don't
	// bother checking the return value.
	printf("ptrace cont 3\n");
	ptrace_cont(target);

	// at this point, if everything went according to plan, we've loaded
	// the shared library inside the target process, so we're done. restore
	// the old state and detach from the target.
	restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
	free(backup);
	free(newcode);

	return 0;
}
