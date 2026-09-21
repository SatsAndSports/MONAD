use std::io::{Read, Write};
use std::time::Duration;

pub(crate) fn boundary(name: &str) {
    if std::env::var("MONAD_FUNDS_BOUNDARY").ok().as_deref() != Some(name) {
        return;
    }
    let address: std::net::SocketAddr = std::env::var("MONAD_FUNDS_IPC")
        .expect("test IPC address")
        .parse()
        .expect("test IPC socket");
    assert!(address.ip().is_loopback());
    let timeout = Duration::from_secs(45);
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, timeout).expect("test IPC connect");
    stream.set_read_timeout(Some(timeout)).unwrap();
    stream.set_write_timeout(Some(timeout)).unwrap();
    stream.write_all(name.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut ack = [0];
    stream
        .read_exact(&mut ack)
        .expect("test boundary acknowledgement");
    assert_eq!(ack, [1]);
}
