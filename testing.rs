use std::process::{Command, Stdio};

fn main() {
    let mut cmd = Command::new("fish");
    cmd.stderr(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stdin(Stdio::piped());

    let mut child = cmd.spawn().unwrap();

    child.wait().unwrap();
}