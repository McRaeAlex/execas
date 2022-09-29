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
