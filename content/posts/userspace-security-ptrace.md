+++
title = "Userspace Security Mechanisms: Ptrace"
date = "2023-09-16"
type = "post"
tags = ["security", "linux", "ptrace", "cloud"]
authors = ["DelusionalOptimist"]
+++

# Introduction
There are several mechanisms for protecting applications at runtime. However, what to use and how effective will it be is subject to the application's environment.

eBPF is a powerful mechanism which is being used commonly for security usecases these days. It provides deep observability by directly instrumenting the OS kernel. However, a side effect of this is the need of privileged access of some form in the system.

It is also noteworthy that cloud platforms recently have started to abstract away infrastructure, hiding many configuration knobs, so that users can have a more smoother and secure experience. An example is AWS Fargate. Available to use with ECS and EKS clusters, it abstracts away the underlying EC2 instances by adding it's own agent in the usual container data plane and further isolates by running single workload per instance. It also restricts certain primitives as an attempt to keep the enviornment secure.

Thus, in this and upcoming blogs I'll be diving deep into a couple of alternate mechanisms which can be used for security without requiring as many privileges.

# ptrace
[ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html) is a system call in \*nix operating systems. It allows a process (tracer) to inspect and manipulate the state of another process (tracee).

But ptrace has existed for a long time. It is very likely that you've used a tool based on ptrace. Debuggers like gdb and delve use ptrace to insert breakpoints into your program, [strace](https://man7.org/linux/man-pages/man1/strace.1.html) uses ptrace to trace syscalls made by an application and so on.

## ptrace 101
In Linux, the ptrace syscall signature looks like:
```
long ptrace(enum __ptrace_request request, pid_t pid,
            void *addr, void *data);
```
* The first argument is a "request" to specify actions to be performed, as defined by [ptrace](https://elixir.bootlin.com/glibc/latest/source/sysdeps/generic/sys/ptrace.h). We'll take a look at some of the requests soon.
* The second argument is PID of the tracee. It's called pid, which is true in context of a single-threaded process but it's actually always a thread ID. If working with a multi threaded process, a ptrace request takes action on a single thread and not the entire process. You'll find process and thread being used interchangeably here as well as in man ptrace.
* The third specifies an address in tracee's address space which the request will act on.
* The fourth is an address in the tracer's address space for storing data to send or retrieve from the request.

### Tracing syscalls with ptrace
A very basic use case of ptrace is to trace syscalls, as seen with strace. Let's try to understand how it works. If you're new to syscall internals, I've included a link in additional references that helped me understand how they are executed.

So, there are two ways a tracer can initialize a trace.
* By attaching to some already running process. Here the tracer sends a `PTRACE_ATTACH` request and waits(man wait) for the tracee to stop. It can also send a `PTRACE_SEIZE` without stopping the process. Though for security, there are limitations to which processes a tracer can attach and modify, implemented with Linux DAC, capabilities and LSMs.
* By forking and executing the process to be traced as it's child. Here, the child process is required to send a `PTRACE_TRACEME` request before TRAP-ping itself, thereby allowing a waiting parent to take control. The tracer then creates a `PTRACE_SYSCALL` or similar request allowing the tracee to continue execution.

There are a few other complexities relating to `PTRACE_EVENT*`s involved when attaching to an existing process but the tracing loop remains the same. We'll be working with the latter for making our examples generic.

To keep things further simple, our examples will be focussed more on single threaded processes. Tracing multithreaded processes involve handling of `PTRACE_EVENT*`s and can make up a blog of their own.

![ptrace init][1]

Now, upon **every** syscall entry/exit, single instruction or signal, the tracee gets trapped and control is given to tracer. We'll come to this later under [#performance](#performance).

Tracer can do whatever it wants with the state of tracee. Well, not whatever but only whatever behaviour is defined by ptrace... at least in the best case scenario :P. There are plenty of requests which can be used to interact with the tracee's state.

For e.g. strace uses `PTRACE_GET_SYSCALL_INFO` to get syscall number and arguments. `PTRACE_PEEK*` and `PTRACE_GET*` are family of requests that allow tracer to read the state while `PTRACE_POKE*` and `PTRACE_SET*` allow changing the state. These requests further are classified based on different process address spaces.

![ptrace tracer loop][2]

### Security Enforcement With ptrace
Now, if we can use ptrace to inspect and change the process state, it should be possible to use it to define what a process can and cannot do. Further, since ptrace can do all this in the userspace itself, we can use it to create a sandbox like environment and do enforcement only in the context of our workloads, reducing the coupling with underlying infrastructure.

Since we know the basics, there is nothing special here. Upon getting trapped, the tracer gets the tracee's registers, matches it with enforcement rules and modifies the reigster pointed by rax (or eax depending on arch), which generally contains the syscall return code, to EPERM (man errno), thus failing the syscall execution. A signal to kill the tracee might be sent as well.

![ptrace-enforcement][3]

## Enough talking. SHOW ME SOME CODE!
Fair enough.

We'll try creating a simple program to demonstrate the above blocking mechanism. We'll be blocking a couple of syscalls, with a generic approach that can be used to block other syscalls as well. Some parts of this code has been borrowed from Liz Rice's [strace-from-scratch](https://medium.com/hackernoon/strace-in-60-lines-of-go-b4b76e3ecd64).

You can find the complete code at https://github.com/DelusionalOptimist/ptrace-box

First, let's initialize the tracer & tracee.
```Go
func main() {
	// to check if user has supplied a command to be executed or not
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <cmd> <args>...\n", os.Args[0])
		os.Exit(1)
	}

	fmt.Println("Trace: ", os.Args[1:])

	// preparing the command to be executed by child process
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	cmd.SysProcAttr = &unix.SysProcAttr{
		// this is equivalent of a child calling PTRACE_TRACEME.
		// upon seeing this attribute the internal function which handles fork and
		// exec sends the request
		Ptrace: true,
	}

	// certain ptrace requests require control at the OS thread level
	// thus we lock the OS thread so that the Go runtime rescheduling doesn't
	// cause unexpected errors
	// ref: https://github.com/golang/go/issues/7699
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// cmd.Start() is a deep wrapper over syscall.forkexec
	// it forks a new child but since we have set ptrace proc attribute,
	// it stops itself and waits for the tracer before executing
	err := cmd.Start()
	if err != nil {
		fmt.Printf("Failed to create a child: %s\n", err.Error())
		os.Exit(1)
	}
	child := cmd.Process.Pid

	// now we wait for the child to get trapped
	wstatus := new(unix.WaitStatus)
	// we'll be using unix.wait4 as cmd.Wait doesn't handle signals well
	_, err = unix.Wait4(child, wstatus, 0, nil)
	if err != nil {
		fmt.Printf("Failed to wait for child. Err: %s\n", err.Error())
		os.Exit(1)
	}

	if wstatus != nil {
		// tracee has stopped itself by sending a trap signal
		// tracer can now take over
		if wstatus.Stopped() && wstatus.StopSignal() == unix.SIGTRAP {
			fmt.Printf("Tracee (%d) trapped...\n", child)
		}
	} else {
		// if the above's not the case, something is wrong
		fmt.Printf("Tracee (%d) status unknown...\n", child)
		os.Exit(1)
	}

	// PTRACE_O_EXITKILL ensures that tracee gets killed when tracee exits thus
	// preventing jailbreaks. Setting this will have effect only after the child
	// process is trapped for a waiting parent
	unix.PtraceSetOptions(child, unix.PTRACE_O_EXITKILL)

	// start tracing
	err = Trace(child, wstatus)
	if err != nil {
		fmt.Printf("Failed to get trace: %s\n", err.Error())
	}

	fmt.Println("Tracer exiting...")
}

func Trace(pid int, status *unix.WaitStatus) error {
	// to be implemented
	return nil
}
```

Upon running the above code with a command, we'll see that the tracee process gets trapped and then the tracer exits, killing the tracee along with it. Had we not set `PTRACE_O_EXITKILL` the tracee would've escaped and completed execution in this situation.

```bash
$ go build -o ptrace-box .; ./ptrace-box cat file.txt
Trace:  [cat file.txt]
Tracee (50347) trapped...
./ptrace-box exiting...
```

Also, what if due to some error the tracer quits before it sets the `PTRACE_O_EXITKILL` option? That would be an escape as well. Since we are working with security, we shouldn't take any chances! The tracee should quit if tracer quits at any point. An easy way to set this is using the [prctl](https://man7.org/linux/man-pages/man2/prctl.2.html) syscall. In Go, you can specify it with just a `SysProcAttr` option. We'll add this to the existing `SysProcAttr` object of `cmd`.
```Go
	cmd.SysProcAttr = &unix.SysProcAttr{
		// this is equivalent of a child calling PTRACE_TRACEME.
		// upon seeing this attribute the internal function which handles fork and
		// exec sends the request
		Ptrace: true,

		// kill the child when parent dies even if the parent is not a tracer
		Pdeathsig: unix.SIGKILL,
	}
```

Let's continue with our tracer logic. Lot of the things I'll be doing will be for `x86_64`. But I'll be adding references along on how you do the same for your arch.

We'll be intercepting the syscall and printing it's number by getting it from the `orig_rax` (only in `x86_64`). Take a look into [man syscall](https://man7.org/linux/man-pages/man2/syscall.2.html) for identifying which register stores the syscall number in your arch. Also, the number might be stored in both `rax` and `orig_rax` registers. However, we'll be using `orig_rax`. Here is an explanation as to [why is orig_eax provided in addition to eax?](https://stackoverflow.com/questions/6468896/why-is-orig-eax-provided-in-addition-to-eax) (eax was i386 equivalent of rax).

```Go
func Trace(pid int, status *unix.WaitStatus) error {
	var (
		err error
		regs unix.PtraceRegs
	)

	// let the execve syscall continue
	err = unix.PtraceSyscall(pid, 0)
	if err != nil {
		return err
	}

	// wait for tracee to get trapped on next syscall
	_, err = unix.Wait4(pid, status, 0, nil)
	if err != nil {
		return err
	}

	// trace until tracee doesn't exit
	for !status.Exited() {
		// when the tracee is in a a syscall-stop
		// do the needed processing
		err = unix.PtraceGetRegs(pid, &regs)
		if err != nil {
			return err
		}

		fmt.Println("syscall NR:", regs.Orig_rax)

		// resume the tracee execution again
		err = unix.PtraceSyscall(pid, 0)
		if err != nil {
			return err
		}

		// wait for tracee to get trapped again
		_, err = unix.Wait4(pid, status, 0, nil)
		if err != nil {
			return err
		}
	}

	fmt.Printf("Tracee (%d) exited...\n", pid)

	return nil
}
```

Upon running this, the output might look something like below. You might see two lines for each syscall because as mentioned earlier, tracee gets trapped on both syscall entry and exit.

```bash
$ go build -o ptrace-box .; ./ptrace-box cat file.txt
Trace:  [cat file.txt]
Tracee (174688) trapped...
syscall NR: 59     # execve
...
A line in file.txt # write file content to stdout
...
syscall NR: 3      # close
Tracee (174688) exited...
Tracer exiting...
```

Now let's understand how we'll actually deny the syscall.

First, we'll need to identify if a syscall is a _blocklisted_ syscall by matching the syscall number.

Next, we'll match one of the parameters passed while making the syscall. For this, we'll need to know the signature of the blocklisted syscall. Refer this [Linux syscalls table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md).

I'll pick up two syscalls for this demo. `openat` and `unlinkat`. Why these two? It'll get cleared soon.
Upon looking it up in the table, you'll find that for `openat`, `const char *filename` is arg1 and is stored in the `%rsi` register in `x86_64`. Same goes for `unlinkat` as well.

Once we have matched the syscall no. and filename, we'll modify the register holding the return value of the syscall i.e. `rax`.
Upon a successful call to `openat`, the value stored in `rax` is a file descriptor to the opened file or an [errno](https://man7.org/linux/man-pages/man3/errno.3.html). For `unlinkat`, the return value is `0` or an errno.
We'll be setting the return value for these to `EPERM`, the generic error sent whenever an operation doesn't have enough permissions to proceed.

Once we set these, the library function calling them should get an error and syscall should get blocked. Seems straight forward, right? There's a catch.

There is no way to stop a syscall. If we change `rax` on syscall-entry-stop then syscall will still run as normal and change the register upon completion.

If we change `rax` value on syscall-exit-stop, we'll be too late. Though this approach might work for syscalls which return a value that the library functions depend on, for e.g. `openat` returns an fd or an error, it still won't work for others which change something while the syscall is run, for e.g. `unlinkat` returns 0 or an error but the file is deleted before syscall-exit-stop.

So is there no way to block a syscall? No, there is a way!

I'm thankful to [Barun](https://twitter.com/daemon1024) for directing me towards [this](https://nullprogram.com/blog/2018/06/23/) blog by Chris Wellons. I realized that the trick is to set the syscall NR (`orig_rax`) as invalid upon syscall-entry-stop. This way the system call dispatcher won't recognize the syscall and thus not run it at all!

Let's try to prove if it works by fiddling around with the `trace()` function. At first we'll only modify `rax`.

```Go
var (
	// constants
	EPERM = uint64(unix.EPERM)
	INVAL = uint64(1)
)

func main() {
	...
	userFilePath, ok := os.LookupEnv("FILE_PATH")
	if !ok {
		fmt.Println("Env var \"FILE_PATH\" must be set...")
		os.Exit(1)
	}

	fmt.Println("Trace: ", os.Args[1:])
	fmt.Println("Block: ", userFilePath)
	...
	// start tracing
	err = Trace(child, wstatus, userFilePath)
	if err != nil {
		fmt.Printf("Failed to trace (%d): %s\n", child, err.Error())
		os.Exit(1)
	}

	fmt.Println("Tracer exiting...")
}

func Trace(pid int, status *unix.WaitStatus, userFilePath string) error {
	var (
		err error
		regs unix.PtraceRegs
	)

	// let the execve syscall continue
	err = unix.PtraceSyscall(pid, 0)
	if err != nil {
		return err
	}

	// wait for tracee to get trapped on next syscall
	_, err = unix.Wait4(pid, status, 0, nil)
	if err != nil {
		return err
	}

	// trace until tracee doesn't exit
	for !status.Exited() {
		// while the tracee is in a syscall-stop
		// do the needed processing
		err = unix.PtraceGetRegs(pid, &regs)
		if err != nil {
			return err
		}

		err = checkAndBlock(pid, &regs, unix.SYS_OPENAT, userFilePath)
		if err != nil {
			return err
		}

		// resume the tracee execution again
		err = unix.PtraceSyscall(pid, 0)
		if err != nil {
			return err
		}

		// wait for tracee to get trapped again
		_, err = unix.Wait4(pid, status, 0, nil)
		if err != nil {
			return err
		}

	}

	fmt.Printf("Tracee (%d) exited...\n", pid)

	return nil
}

func checkAndBlock(pid int, regs *unix.PtraceRegs, syscallNR uint64, userFilePath string) error {
	if regs.Orig_rax == syscallNR {
		// the largest path value that can be stored in the RSI is
		// PATH_MAX bytes long
		buff := make([]byte, unix.PathMax)

		// `PTRACE_PEEKTEXT` request to get file path value from RSI register
		// address in tracee's address space
		n, err := unix.PtracePeekText(pid, uintptr(regs.Rsi), buff)
		if err != nil && n == 0 {
			return err
		}

		// there might be garbage data due to the size of our buffer
		// the string that we need however is null terminated
		nullIdx := bytes.IndexByte(buff[:], 0)

		// get the absolute path w.r.t tracee from the filename
		filePath := absPath(pid, string(buff[:nullIdx]))

		// match file path and set the return value (RAX) as EPERM
		// with a PTRACE_SET_REGS request
		if userFilePath == filePath {
			regs.Rax = -EPERM
			err := unix.PtraceSetRegs(pid, regs)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// get absolute path
func absPath(pid int, p string) string {
	// if relative path
	if !path.IsAbs(p) {
		return path.Join(getProcCwd(pid), p)
	}
	return path.Clean(p)
}

// read cwd from procfs
func getProcCwd(pid int) string {
	fileName := "/proc/self/cwd"
	if pid > 0 {
		fileName = fmt.Sprintf("/proc/%d/cwd", pid)
	}
	s, err := os.Readlink(fileName)
	if err != nil {
		return ""
	}
	return s
}
```
Upon executing this with a command that tries to access `file.txt`, the output may look something like:
```bash
# rudraksh @ pingu in ~/dev/ptrace-box [21:08:00]
$ cat file.txt
hello

# rudraksh @ pingu in ~/dev/ptrace-box [21:08:05]
$ go build -o ptrace-box .; FILE_PATH=$(pwd)/file.txt ./ptrace-box cat file.txt
Trace:  [cat file.txt]
Block:  /home/rudraksh/dev/ptrace-box/file.txt
Tracee (365903) trapped...
cat: file.txt: Operation not permitted
Tracee (365903) exited...
Tracer exiting...

```

Cool, we can block `openat`.
Now change the function call to `checkAndBlock()` for blocking `unlinkat` and create a violation using the `rm` command:
```Go
		err = checkIfBlocked(pid, &regs, unix.SYS_UNLINKAT, userFilePath)
```
```bash
# rudraksh @ pingu in ~/dev/ptrace-box [21:09:43]
$ cat file.txt
hello

# rudraksh @ pingu in ~/dev/ptrace-box [21:09:45]
$ go build -o ptrace-box .; FILE_PATH=$(pwd)/file.txt ./ptrace-box rm file.txt
Trace:  [rm file.txt]
Block:  /home/rudraksh/dev/ptrace-box/file.txt
Tracee (366825) trapped...
rm: cannot remove 'file.txt': Operation not permitted
Tracee (366825) exited...
Tracer exiting...

# rudraksh @ pingu in ~/dev/ptrace-box [21:09:49]
$ cat file.txt
cat: file.txt: No such file or directory
```

We have blocked the syscall according to this output! But `file.txt` has been still removed : (
As expected, the _operation not permitted_ is just because of glibc's wrapper for the syscall.

Now let's try by setting the syscall NR as invalid in `checkAndBlock()`:
```Go
		// match file path and set the return value (RAX) as EPERM
		// and Orig_rax to invalid syscall (0)
		// with a PTRACE_SET_REGS request
		if userFilePath == filePath {
			// hacky way to specify a negative u64
			regs.Orig_rax = -INVAL
			regs.Rax = -EPERM
			err := unix.PtraceSetRegs(pid, regs)
			if err != nil {
				return err
			}
		}
```

Upon running this:
```bash
# rudraksh @ pingu in ~/dev/ptrace-box [10:22:01]
$ cat file.txt
hello

# rudraksh @ pingu in ~/dev/ptrace-box [10:22:02]
$ go build -o ptrace-box .; FILE_PATH=$(pwd)/file.txt ./ptrace-box rm file.txt
Trace:  [rm file.txt]
Block:  /home/rudraksh/dev/ptrace-box/file.txt
Tracee (26158) trapped...
rm: cannot remove 'file.txt': Operation not permitted
Tracee (26158) exited...
Tracer exiting...

# rudraksh @ pingu in ~/dev/ptrace-box [10:22:05]
$ cat file.txt
hello
```

So `rm` gets actually blocked now!

One last optimization we can do is to modify registers only on syscall entry. The effect will be same and we'll have better performance!

```Go
func Trace(pid int, status *unix.WaitStatus, userFilePath string) error {
	var (
		...
		// to keep track of syscall entry stops
		// ptrace leaves it upto the tracer to do so
		entry = true
	)
	...
	// trace until tracee doesn't exit
	for !status.Exited() {
		// while the tracee is in a syscall-entry-stop
		// do the needed processing
		if entry {
			err = unix.PtraceGetRegs(pid, &regs)
			if err != nil {
				return err
			}

			err = checkAndBlock(pid, &regs, unix.SYS_UNLINKAT, userFilePath)
			if err != nil {
				return err
			}
		}
		...
		entry = !entry
	}
	...
}
```

That's it. We've built ourselves a simple enforcer which can be used to blocklist sycalls.

While running an application, you can specify it as an argument of `ptrace-box` which will ensure you have a sandbox with a set of blocklisted or whitelisted syscalls.

## Performance
Remember I mentioned earlier that the tracee would be trapped and wait for tracer at every syscall entry/exit or signal. Yes, every here meant EVERY. Thus there are performance implications of using ptrace. Read [this](https://gvisor.dev/blog/2023/04/28/systrap-release/) analysis by gvisor on moving away from ptrace based sandboxing due to performance implications.

There are a couple of workarounds.
* Set `PTRACE_O_TRACESYSGOOD`: If intercepting syscalls is the only goal, one can set the option `PTRACE_O_TRACESYSGOOD`. It would modify the signal received by `wait` whenever the tracee is in a syscall stop. Thus, the tracer can use this to avoid unecessary inspection of tracee state when the trap is not due to a syscall.
* Seccomp: In simple terms, seccomp allows creating filters on syscalls. A potential filter is to allow tracing of only a limited number of syscalls. The tracer can then chose to stop only on `PTRACE_EVENT_SECCOMP` rather than each and every event, greatly reducing the number of traps. See [this](https://www.youtube.com/watch?v=fAcI3NErQw0) talk on how strace uses seccomp for filtering syscalls and improving performance.

We'll look at these mechanisms in future posts.

# Conclusion
Though ptrace based enforcement provides good security in context of unprivileged environments, it still has it's limitations and can't be used to protect applications at the system level

# Additional References
- https://linux-kernel-labs.github.io/refs/heads/master/lectures/syscalls.html
- https://www.alfonsobeato.net/c/modifying-system-call-arguments-with-ptrace/
- https://blog.nelhage.com/2010/08/write-yourself-an-strace-in-70-lines-of-code/

[1]: /ptrace-init.png
[2]: /ptrace-loop.png
[3]: /ptrace-enforcement.png
