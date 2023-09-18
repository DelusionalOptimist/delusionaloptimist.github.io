+++
title = "Userspace security"
date = "2023-09-16"
type = "post"
tags = ["security", "linux", "ptrace", "seccomp", "LD_PRELOAD", "cloud"]
authors = ["DelusionalOptimist"]
+++

# Introduction
There are several mechanisms for protecting your workloads at runtime. However, what to use and how effective will it be is subject to the workload's environment.

Many runtime seucrity tools use eBPF for enforcing runtime security. It is a powerful mechanism which provides deep observability by directly instrumenting the OS kernel. However, a side effect of this is the need of privileged access to workloads' underlying infrastructure.

It is also noteworthy that cloud platforms recently have started to abstract away infrastructure, hiding many configuration knobs, so that users can have a more smoother and secure experience. An example is AWS Fargate. Available to use with ECS and EKS clusters, it abstracts away the underlying EC2 instances by adding it's own agent in the usual container data plane and further isolating by running single workload per instance. It also restricts certain primitives as an attempt to keep the enviornment secure.

So, the ask is to create a security tool which can work without much coupling with the underlying hosts.

# ptrace
ptrace is a syscall in \*nix operating systems. It allows a process (tracer) to inspect and manipulate the state of another process (tracee).

But ptrace has existed for a long time. It is very likely that you've used a tool based on ptrace. Debuggers like gdb and delve use ptrace to insert breakpoints into your program, strace uses ptrace to trace syscalls made by an application and so on.

### How does ptrace work
![ptrace-basics][1]

#### Enforcement with ptrace
Now, if we can use ptrace to inspect and change the process state, it should be possible to use it to define what an application can and cannot do. Further, since ptrace can do all this in the userspace itself, we can use it to create a sandbox like environment and do enforcement only in the context of our workloads, reducing the coupling with underlying infrastructure.

![ptrace-enforcement][2]

---WIP---
### SHOW ME SOME CODE!
Fair enough.

We'll try creating a simple enforcer which will block the openat syscall made on a file specified by user. There are two ways by which a process can trace another, one of them is by executing the tracee as a child of the tracer. The other one involves the tracer attaching to the tracee while it is already executing.

```Go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"syscall"
)

var EPERM uint64 = ^uint64(syscall.EACCES - 1)

func main() {
	var err error
	var regs syscall.PtraceRegs

	fmt.Println("Run: ", os.Args[1:])

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	filePath, ok := os.LookupEnv("FILE_PATH")
	if ok {
		fmt.Println("File path to match:", filePath)
	}

	cmd.Start()
	err = cmd.Wait()
	if err != nil {
		fmt.Printf("Wait err: %v\n\n", err.Error())
	}

	pid := cmd.Process.Pid
	exit := true

	for {
		if exit {
			err = syscall.PtraceGetRegs(pid, &regs)
			if err != nil {
				break
			}
			if regs.Orig_rax == syscall.SYS_OPENAT {
				file := absPath(pid, getString(pid, uintptr(regs.Rsi)))
				if filePath != "" && file == filePath {
					regs.Orig_rax = ^uint64(0)
					regs.Rax = EPERM
					_ = syscall.PtraceSetRegs(pid, &regs)
				}
			}
		}
		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			panic(err)
		}
		_, err = syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			panic(err)
		}

		exit = !exit
	}

}

func clen(b []byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			return i
		}
	}
	return len(b) + 1
}

func getString(pid int, addr uintptr) string {
	buff := make([]byte, syscall.PathMax)
	syscall.PtracePeekData(pid, addr, buff)
	return string(buff[:clen(buff)])
}

func absPath(pid int, p string) string {
	// if relative path
	if !path.IsAbs(p) {
		return path.Join(getProcCwd(pid), p)
	}
	return path.Clean(p)
}

// getProcCwd gets the process CWD
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

[1]: /ptrace-1.png
[2]: /ptrace-2.png
