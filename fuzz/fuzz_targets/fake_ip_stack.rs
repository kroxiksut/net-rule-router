#![no_main]
//! Packets entering the user-space stack: the input is cut into packets and
//! fed through a mock adapter to the real poll loop, with a mock dialer so
//! nothing leaves the process.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use libfuzzer_sys::fuzz_target;
use nrr_platform_api::fake_ip::tun::{MockTunAdapter, TunAdapterConfig, TunAdapterPort};
use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpPoolConfig, FakeIpScope};
use nrr_service_runtime::fake_ip::dialer::MockRelayDialer;
use nrr_service_runtime::fake_ip::relay::{FixedRouteSelector, RelayCore, StaticUpstreamResolver};
use nrr_service_runtime::fake_ip::stack::{FakeIpStack, StackWaker};

const MAX_INPUT: usize = 64 * 1024;
const MAX_PACKETS: usize = 64;
const STEPS_AFTER_INPUT: u64 = 8;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let mut allocator = FakeIpAllocator::default();
    let Ok(binding) = allocator.allocate("host.example") else {
        return;
    };
    let relay = RelayCore::new(
        Arc::new(Mutex::new(allocator)),
        FakeIpScope::enabled(Vec::<String>::new()),
        Arc::new(
            StaticUpstreamResolver::new()
                .with("host.example", &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
        ),
        Arc::new(FixedRouteSelector(nrr_shared::RouteRole::Primary)),
    );
    let (adapter, state) = MockTunAdapter::new();
    let Ok(device) = adapter.open(&TunAdapterConfig::default()) else {
        return;
    };
    let mut stack = FakeIpStack::new(
        device,
        &FakeIpPoolConfig::default(),
        relay,
        Arc::new(MockRelayDialer::new()),
        StackWaker::new(),
    )
    .with_socket_buffer_bytes(4096);

    // First byte: how many packets the rest is cut into; a zero means one.
    let (count, body) = match data.split_first() {
        Some((n, rest)) => (usize::from(*n).clamp(1, MAX_PACKETS), rest),
        None => return,
    };
    let chunk = body.len().div_ceil(count).max(1);
    for packet in body.chunks(chunk) {
        let mut packet = packet.to_vec();
        // Most packets are retargeted at the allocated fake address so the
        // relay path, not only the "not for us" exit, is reached.
        if packet.len() >= 20 && packet[0] >> 4 == 4 && packet[1] & 1 == 0 {
            packet[16..20].copy_from_slice(&binding.v4.octets());
        }
        state.push_inbound(packet);
    }

    let mut now_ms = 0u64;
    let mut budget = u64::try_from(count).unwrap_or(1) + STEPS_AFTER_INPUT;
    while budget > 0 {
        budget -= 1;
        now_ms += 10;
        if stack.step(now_ms).is_err() {
            break;
        }
    }
    let _ = state.written_packets();
});
