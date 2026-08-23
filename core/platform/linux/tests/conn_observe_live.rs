//! One live test against the real mechanism: a connection this test makes must
//! come back attributed to this test.
//!
//! Needs no root — a process can always read its own descriptors — so it runs
//! wherever the daemon builds. What it proves is the join the pure tests cannot:
//! that the socket the kernel lists and the descriptor the process holds are
//! matched through the same inode.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::io::Read;
use std::net::{TcpListener, TcpStream};

use nrr_platform_api::conn_observe::ConnectionObservationSource;
use nrr_platform_linux::conn_observe::ProcfsConnectionObserver;

#[test]
fn a_connection_this_process_makes_is_observed_and_attributed_to_it() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local listener");
    let target = listener.local_addr().expect("the listener has an address");

    let observer = ProcfsConnectionObserver::new();
    // Everything already open belongs to the previous state of the machine; the
    // interesting event is what happens next.
    let _ = observer.drain();

    let client = TcpStream::connect(target).expect("connect to the local listener");
    let (mut accepted, _) = listener.accept().expect("accept the connection");

    let observed = observer.drain();
    let ours = observed
        .iter()
        .find(|o| o.remote == target && o.pid == std::process::id())
        .unwrap_or_else(|| {
            panic!("the connection was not observed, or not attributed:\n{observed:#?}")
        });

    let exe = ours
        .process_path
        .as_deref()
        .expect("the observation must name the binary that made the connection");
    assert!(
        exe.contains("conn_observe_live"),
        "the connection was attributed to the wrong binary: {exe}",
    );
    // SAFETY: `getuid` reads this process's own credential and cannot fail.
    #[allow(unsafe_code)]
    let uid = unsafe { libc::getuid() };
    assert_eq!(
        ours.user_sid.as_deref(),
        Some(nrr_platform_api::enforcement::UserPrincipal::from_linux_uid(uid).as_stored()),
        "the connection was attributed to the wrong user",
    );

    // A socket is an event once: reporting it every poll would turn one
    // connection into a stream of identical rows in the trace.
    let again = observer.drain();
    assert!(
        !again
            .iter()
            .any(|o| o.remote == target && o.pid == std::process::id()),
        "the same connection was reported twice",
    );

    drop(client);
    let mut sink = Vec::new();
    let _ = accepted.read_to_end(&mut sink);
}
