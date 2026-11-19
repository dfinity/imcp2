//! The binary's shutdown, end to end: spawned the way an AI client spawns
//! it, taken through the MCP handshake over its pipes, and stopped each way
//! a client stops a stdio server. What is under test is that the process
//! ends, promptly and with a clean exit: a server that outlives its client,
//! or that has to be killed, is one whose shutdown path — where a running
//! deploy is stopped and waited for — never ran to its end.
//!
//! Nothing here reaches the network: the server is pointed at an address
//! nothing listens on, and no tool is called.

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

/// Long enough for a loaded CI machine, far short of a hang.
const SOON: Duration = Duration::from_secs(30);

/// A running `imcp2-local` that has answered `initialize`, with the pipe a
/// client would hold. Killed when dropped, so a failed assertion leaves no
/// process behind.
struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    _home: tempfile::TempDir,
}

impl Server {
    fn serving() -> Self {
        // Its own home: the deploy directory is made under the local data
        // directory as the server starts.
        let home = tempfile::tempdir().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_imcp2-local"))
            .env("HOME", home.path())
            .env("XDG_DATA_HOME", home.path().join("data"))
            .env("LOCALAPPDATA", home.path().join("data"))
            .env("IMCP2_NO_OPEN", "1")
            .env("IMCP2_IC_URL", "http://127.0.0.1:9")
            .env_remove("IMCP2_FETCH_ROOT_KEY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the binary starts");
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut server = Self { child, stdin: None, _home: home };

        let send = |stdin: &mut ChildStdin, message: serde_json::Value| {
            writeln!(stdin, "{message}").and_then(|()| stdin.flush()).expect("the pipe is open");
        };
        send(
            &mut stdin,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "shutdown-test", "version": "0" }
                }
            }),
        );
        // Read on a thread, so a server that never answers fails the test
        // instead of hanging it.
        let (answered, answer) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = answered.send(line);
        });
        let line = answer.recv_timeout(SOON).expect("initialize is answered");
        let reply: serde_json::Value =
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON ({e}): {line:?}"));
        assert_eq!(reply["id"], 1, "{reply}");
        assert!(reply["result"]["serverInfo"].is_object(), "{reply}");
        send(
            &mut stdin,
            serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        );
        server.stdin = Some(stdin);
        server
    }

    /// How the process ended, if it did within [`SOON`].
    fn ended(&mut self) -> Option<ExitStatus> {
        let deadline = Instant::now() + SOON;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// The client closes the pipe: the ordinary way a stdio server is stopped.
#[test]
fn the_server_ends_cleanly_when_its_client_closes_the_pipe() {
    let mut server = Server::serving();
    drop(server.stdin.take());
    let status = server.ended().expect("the server ends once its pipe is closed");
    assert!(status.success(), "{status}");
}

// The client, a service manager or Ctrl-C signals it, with the pipe still
// open: the server stops of its own accord — a clean exit, not a death by
// the signal, which would be the shutdown path never having run — and does
// not wait on a pipe nobody is going to close.
#[cfg(unix)]
#[test]
fn the_server_ends_cleanly_on_a_signal_with_its_pipe_still_open() {
    for signal in ["TERM", "INT"] {
        let mut server = Server::serving();
        let sent = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(server.child.id().to_string())
            .status()
            .expect("kill runs");
        assert!(sent.success(), "SIG{signal} was not sent: {sent}");
        let status =
            server.ended().unwrap_or_else(|| panic!("SIG{signal}: the server is still running"));
        assert!(status.success(), "SIG{signal}: {status}");
    }
}
