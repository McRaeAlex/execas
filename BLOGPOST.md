# Creating an alternative way to run commands as another user

I want to understand how many of the everyday commands I run work. Often I find the best way to do that is to read the code and rewrite it / trace the flow.

However, this time I found a bunch of rewrites / alternatives which I found really interesting.

- pfexec - A illumos / solaris command which relies on the profiles and rbac features of the OS
- doas - A cross platform utility to run commands as another user, created as part of the OpenBSD project
- sudo - A cross platform utility to run commands as another user, created for Linux

Notably `doas` and `sudo` as very similar, the differ in their configuration files and how they exec the command. pfexec differs in that it relies on illumos specific behavior and files.

## How it works

Without really looking at the source code of the already existing utilities i imagined their were some pretty straight forward systemcalls for this functionality.

For replacing the process with a new command [execvp]() exists. For changing the user for the process we have [seteuid]() and [setuid]() for setting the **effective** user id and **real** user id for the current process.

Digging into the difference between effective and real user we come to [this wikipedia article](https://en.wikipedia.org/wiki/User_identifier) which explains that the real user id is the process owner, effective user id is the user we want to pretend to be or act as. There is a difference between the real and effective user id's because when we no longer want to act as the effective user we must know what to reset the effective user as.

Example showing effect and real users throughout the execution of a simple c program

```c
#include <stdio.h>
#include <unistd.h>

int main()
{
    uid_t ruid, euid;
    ruid = getuid();
    euid = geteuid();

    printf("real: %d effective: %d\n", ruid, euid);
    return 0;
}
```

Running this program as normally and then with sudo I expect the effective id to change when running with sudo.

```bash
$ ./print_uids
real: 501 effective: 501

$ sudo ./print_uids
real: 0 effective: 0
```

Huh? `sudo` changed both the real and effective uids. This doesn't seem right.. lets look at the man page.

From the diagnostics page

> sudo must be owned by uid 0 and have the setuid bit set\
> sudo was not run with root privileges. The sudo binary does not have the correct owner or permissions. It must be owned by the root user and have the set-user-ID bit set

This is interesting, the set-user-ID bit enabled sudo to run as root even if a non root user runs it.

```
-r-s--x--x  1 root  wheel  1246528 May  9 14:30 /usr/bin/sudo
   ^ this is the set-user-ID bit which means run the command as the owner of the file in this case root
```

But according to the `getuid` man page

> The real user ID is that of the user who has invoked the program. As the effective user ID gives the process additional permissions during execution of “set-user-ID” mode processes, getuid() is used to determine the real-user-id of the calling process.

Well it turns out that one can change the real and effective user ids depending on the unix like environment you are on. Theres a great paper on this [Setuid Demystified](https://web.ecs.syr.edu/~wedu/minix/projects/setuid_paper.pdf) by Hao Chen, David Wagner, and Drew Dean.

So it turns out that the real uid and effective uid are going to depend on the program you use for privilege escalation. Knowing this, we can rewrite out program above but this time install it into the system, once with the setuid bit set and another without it to compare the results.

```
# build the binary
cc -o execas src/execas.c

# create a copy
cp execas rootexecas

# set the file owner to root (and group)
chown root:root ./rootexecas

# set the setuid bit
chmod u+s ./rootexecas
```

... the behavior is the same. WTF.

After searching around i found someone in a similar situation. Interestingly on the exact same setup as me. [link](https://stackoverflow.com/questions/62792097/using-setuid-inside-a-docker-container)
maybe a really linux machine would work better than docker? For clarity the permissions are the exact same.

```
ls -la ./rootexecas /usr/bin/sudo
-rwsr-xr-x 1 root root   9672 Aug 26 22:51 ./rootexecas
-rwsr-xr-x 1 root root 178432 Feb 27  2021 /usr/bin/sudo
```

My only thought is something is preventing my binary from running as root. (busybox, nosuid mount, etc..)

So it turns out porting this to MacOS we get expected output!

```
./rootexecas
real: 501 effective: 0
```

## Back to the how it works

So to recap the binary that is allowing the privilege escalation has the set uid bit set and its owner as root.

Then program (`sudo`, `doas`) will check to make sure the user has the correct permissions to act as root.
This is usually done by rechecking the non root users password and checking the something like the sudoers file for the permissions.

Finally the program will run the command that the user specified either using fork (`sudo`) or execvpe (`doas`).

### Role Based Access Control

Using this behavior is becomes easy to see how role based access control might work.
Start by creating a user for each _role_ you want in the system and give that role the permissions you want. Then assign real users roles and allow them to call some binary with the set uid bit and root owner which checks which role they can assume and run the command as that role.

This is my best guess at how `pfexec` works.

## Writing execas

Now that we know the basic structure of these programs we can write one. Though I have used C in this blog post until now I am more comfortable with Rust

For the scafolding of the app we will write out the steps and use a simple command as the example program.

```rust
fn main() {
    // get the command
    let command = "echo HELLO";

    // check to make sure we are root (effective user id). if not we can try to run some diagnostics

    // see if the user can be root or the user they are wanted to act as

    // exec the command given by the user
}
```

Okay lets work on checking that we are root or can act as root. In this case we will check that our effective user id is 0.

```rust
use nix::unistd::{geteuid, getuid};

fn main() {
    ...
    // check to make sure we are root (effective user id). if not we can try to run some diagnostics
    let euid = geteuid();

    if !euid.is_root() {
        // run diagnostics and exit appropriately
        eprintln!("You're not root :(");
        return;
    }
    ...
}
```

We are going to ignore errors and other stuff for now and focus on the happy path.

Okay next we can check the actual (non root) users password and then check some file `/etc/execas.conf` to see if they can become the user they want. For now the `execas.conf` will just be a text file with a username on each line.
If that user should be able to have root access their username will be there.

```rust

```

From here we can exec the command. Both `doas` and `sudo` setup the environment like its the effective users but for my program I will ignore that and just run the command like normal.

```rust

```

And thats about it. From here theres many improvements to be made

- [ ] Allow the user to imitate other users
- [ ] Add better error handling
- [ ] Add the diagnostics for when the command fails for non _normal_ reasons (setuid bit not set, etc)
- [ ] Packaging for different \*nix like operating systems

## Other forms of privilege escalation

One this about this form of privilege escalation is that it feels very scary. If you can get a binary onto a machine with the set uid bit and owner of root you can gain root access. Binaries with the set-uid-bit set therefore must be cautious about security vulnerabilities and should attempt to limit the damage if one occurs.
I believe openbsd's `pledge` is a good way of limiting the damage that can be done.

However it got me wondering how other operating systems handle privilege escalation.
