//!
//! This demo program will redirect UDP traffic from port 9875 to 9876.
//!
//! You can test this program on your loopback device using the following example
//! UDP server:
//!
//!   use std::io;
//!   use tokio::net::UdpSocket;
//!
//!   #[tokio::main]
//!   async fn main() -> io::Result<()> {
//!       let sock = UdpSocket::bind("127.0.0.1:9876").await?;
//!
//!       let mut buf = [0; 1024];
//!       loop {
//!           let (len, addr) = sock.recv_from(&mut buf).await?;
//!           println!("{:?} bytes received from {:?}", len, addr);
//!           println!("message received: {}", String::from_utf8_lossy(&buf));
//!       }
//!   }
//!
//! With a Cargo.toml containing:
//!
//!   [dependencies]
//!   tokio = { version = "1", features = ["full"] }
//!
//! Send a message on port 9875 with netcat to have it redirected by the XDP
//! program to the above server listening on 9876:
//!
//!   $ echo "testing port redirect" | nc -u localhost 9875
//!
//! If everything is working, you should see the following message appear in the
//! output of the server:
//!
//!   $ cargo run
//!   Finished dev [unoptimized + debuginfo] target(s) in 0.01s
//!   Running `target/debug/udp-listen`
//!   22 bytes received from 127.0.0.1:36611
//!   message received: testing port redirect
//!
#![no_std]
#![no_main]
use core::mem::size_of;
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[xdp]
fn portredirect(ctx: XdpContext) -> XdpResult {
    let transport = ctx.transport()?;

    // only handle IP packets
    let ip = match ctx.ip() {
        Err(NetworkError::NoIPHeader) => return Ok(XdpAction::Pass), // not an IP packet
        Err(_err) => unreachable!(),
        Ok(hdr) => hdr,
    };

    // pass anything that isn't coming in on 9875
    if transport.dest() != 9875 {
        return Ok(XdpAction::Pass);
    }

    // pass anything that isn't UDP traffic
    if !matches!(transport, Transport::UDP(_)) {
        bpf_trace_printk(b"received non-UDP traffic, skipping\0");
        return Ok(XdpAction::Pass);
    };

    bpf_trace_printk(b"got UDP traffic on port 9875\0");

    // change the destination port from 9875 to 9876
    unsafe {
        let addr = ip as usize + ((*ip).ihl() * 4) as usize;
        ctx.check_bounds(addr, addr + size_of::<usize>())?; // verify the pointer will be in bounds
        let hdr = addr as *mut udphdr;
        (*hdr).dest = u16::from_be(9876);
    };

    bpf_trace_printk(b"redirected UDP traffic from port 9875 to 9876\0");

    Ok(XdpAction::Pass)
}
