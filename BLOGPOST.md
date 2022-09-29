# Creating an alternative sudo, an exploration of privilege escalation in Unix-like environments

I want to understand how many of the everyday commands I run work. Often I find the best way to do that is to read the code and rewrite it / trace the flow. This blog post documents my journey to understanding `sudo` and how root is access by users.

Other than `sudo` there are a couple interesting programs for privilege escalation depending on the environment

- pfexec - A illumos / solaris command which relies on the profiles and rbac features of the OS
- doas - A cross platform utility to run commands as another user, created as part of the OpenBSD project
- sudo - A cross platform utility to run commands as another user, created for Linux

## How it works

Without looking at the source code I imagine the logic looked as follows.

1. check that the user calling the utility has the permission to use it
2. change users
3. exec the requested command

[execvpe]() exists for (3)
[seteuid]() and [setuid]() for setting the **effective** user id and **real** user id for the current process.

Digging into the difference between effective and real user we come to [this wikipedia article](https://en.wikipedia.org/wiki/User_identifier) which explains that the real user id is the process owner, effective user id is the user we want to pretend to be or act as. There is a difference between the real and effective user id's because when we no longer want to act as the effective user we must know what to reset the effective user as.

Okay simple enough! Lets write a quick program to see the user ids in action.

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

> The invoking user's real (not effective) user-ID is used to determine the user name with which to query the security policy.

This makes a little more sense now. Since some programs might check the real user id instead of the effective for permissions, sudo changes both. This brings up another question, how did sudo change the real user id to root?

From the mac `setuid` man page

> The setuid() function is permitted if the effective user ID is that of the super user, or if the specified user ID is the same as the effective user ID.

Okay well that means sudo's effective user id must be root.

From the mac `setuid` man page regarding `seteuid`

> Unprivileged processes may only set the effective user ID to the real user ID, the effective user ID or the saved set-user-ID.

At a glance this seems circular, but what is this `saved set-user-ID`?

The `setuid` man pages points us to `intro(2)` which helps explain it!

> When a process executes a new file, the effective user ID is set to the owner of the file if the file is set-user-ID...

This helps explain it! The set-user-ID permission on the file allows the effective user id to be changed and then using that we can the real user id! So `sudo` must be owned by root and have this bit set.

```
-r-s--x--x  1 root  wheel  1246528 May  9 14:30 /usr/bin/sudo
   ^ this is the set-user-ID bit which means run the command as the owner of the file in this case root
```

:) Lets modify out program that prints the real and effective user ids to be owned by root and have this bit set. Here is the updated makefile

```

execas: src/execas.c
    # build the binary
	cc -Wall -Wextra -lc -o execas src/execas.c

	# copy the file
	cp execas rootexecas

	# set the file owner to root (and group)
	chown root ./rootexecas

	# set the setuid bit
	chmod u+s ./rootexecas

.PHONY: clean ls
clean:
	rm rootexecas execas

ls:
	ls -la execas rootexecas
```

Now when we run rootexecas we expect the effective user id to be root but the real should stay the same.

```
./rootexecas
real: 501 effective: 0
```

!!

### Recap

1. The executable must be owned by root and have the `set-user-ID` bit set
2. On execution by a user the effective user id is changed to the owner (root) by the operating system.
3. `setuid` is used to set the real user id to the effective user id (root)
4. `exec` is used to replace the process with the one the calling user wanted

Now we have the happy path. This is _basically_ how `pfexec`, `doas`, and `sudo` work but we are actually missing a step.

### The missing step (between 2 and 3)

_Any_ user can now get root privileges but running the described program. This presents a security problem and each tool handles it slightly differently.

sudo - sudoers file\
doas - doas.conf\
pfexec - ? something something rbac (i forgot to look into it) ?

The program needs to check these files to see if the calling user is allowed to act as root (or some other user).

#### Some other steps missing

sudo, doas - checks the effective user id and if its not root tries to diagnose it (check the owner of the exec, check the set-user-ID bit, etc)\
doas - uses pledge to reduce its own ability to make other system calls

## Writing our own (execas)

With our updated understanding of the privilege escalation in unix we can write the scaffolding.

I have chosen a command which will demonstrate the change in effective user id.

```rust
fn main() {
    // get the command from the user
    let args = ["whoami"].map(|s| CString::new(s).unwrap());

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

Okay next we can ~~check the actual (non root) users password and then~~ check some file `/etc/execas.conf` to see if they can become the user they want. For now the `execas.conf` will just be a text file with a username on each line.
If that user should be able to have root access their username will be there.

Note: We won't check the password because its annoying.
Note: the execas.conf should be stored in a place users cannot modify it (without the correct permissions)

```rust
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};

use nix::unistd::User;

fn main() {
    ...
    // force the user to reauthenticate
    let real_user = User::from_uid(ruid)
        .expect("Failed to get username from ruid")
        .expect("No username for that uid");

    let mut given_password = String::new();
    print!("password: ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut given_password)
        .expect("Failed to read password from stdin");

    // TODO: compare given_password and real_user.password and ensure they match

    // check the conf file to make they are suppose to be able to run the command
    let mut conf_f = File::open("./execas.conf").expect("Could not read execas conf file");
    let mut conf_str = String::new();
    conf_f
        .read_to_string(&mut conf_str)
        .expect("Failed to read conf file");

    let allowed_users: Vec<&str> = conf_str
        .split('\n')
        .map(|user_txt| user_txt.trim())
        .collect();

    if !allowed_users.contains(&real_user.name.as_str()) {
        eprintln!("user {} is not found in execas.conf", real_user.name);
        return;
    }
    ...
}
```

From here we can exec the command. Both `doas` and `sudo` setup the environment like its the effective users but for my program I will ignore that and just run the command like normal.

```rust
fn main() {
    use nix::unistd::execvp;
    // exec the command the user is trying to run
    let command = &args[0];
    execvp(command, &args).unwrap();
}
```

Thats it on the code side of things! All together it looks like this

```rust
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};

use nix::unistd::execvp;
use nix::unistd::User;
use nix::unistd::{geteuid, getuid};

fn main() {
    // get the command
    let args = ["whoami"].map(|s| CString::new(s).unwrap());

    // check to make sure we are root (effective user id). if not we can try to run some diagnostics
    let euid = geteuid();
    let ruid = getuid();

    if !euid.is_root() {
        // run diagnostics and exit appropriately
        eprintln!("You are not root! :(");
        return;
    }

    // force the user to reauthenticate
    let real_user = User::from_uid(ruid)
        .expect("Failed to get username from ruid")
        .expect("No username for that uid");

    let mut given_password = String::new();
    print!("password: ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut given_password)
        .expect("Failed to read password from stdin");

    // TODO: compare given_password and real_user.password and ensure they match

    // check the conf file to make they are suppose to be able to run the command
    let mut conf_f = File::open("./execas.conf").expect("Could not read execas conf file");
    let mut conf_str = String::new();
    conf_f
        .read_to_string(&mut conf_str)
        .expect("Failed to read conf file");

    let allowed_users: Vec<&str> = conf_str
        .split('\n')
        .map(|user_txt| user_txt.trim())
        .collect();

    if !allowed_users.contains(&real_user.name.as_str()) {
        eprintln!("user {} is not found in execas.conf", real_user.name);
        return;
    }

    // exec the command the user is trying to run
    let command = &args[0];
    execvp(command, &args).unwrap();
}

```

Using a makefile we can build this and update the file to have the correct permissions!

```make
execas:
	# install the binary into the bin folder
	cargo install --path . --root .

	# set the file owner to root (and group)
	chown root ./bin/execas

	# set the setuid bit
	chmod u+s ./bin/execas
```

And running this binary (which calls whoami) produces

```
$ ./bin/execas
root
```

And thats about it. From here theres many improvements to be made

- [ ] Allow the user to run other commands
- [ ] Allow the user to imitate other users
- [ ] Add better error handling
- [ ] Add the diagnostics for when the command fails for non _normal_ reasons (setuid bit not set, etc)
- [ ] Packaging for different \*nix like operating systems

# Conclusion

This form of privilege escalation feels very scary as it can be very easy to have a set-user-ID binary on your system without being aware of it. Binaries with the set-uid-bit set therefore must be cautious about security vulnerabilities and should attempt to limit the damage if one occurs.
I believe openbsd's `pledge` is a good way of limiting the damage that can be done.

This experience also got me interesting in alternative forms of privilege escalation, maybe another blog post! :)
