//! Datagrams: bind, forward, reply, expire.
//!
//! UDP has no handshake and no close, so none of the TCP flow machinery
//! applies: a client is remembered by its (address, port), its replies are
//! fanned back, and it is retired by an idle timer rather than by a FIN.
//! Port-unreachable is the only refusal it can express.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

impl FakeIpStack {
    /// Bind a UDP socket for a fresh datagram to an in-scope fake endpoint.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn maybe_open_udp(&mut self, packet: &ParsedPacket) {
        let local = packet.key.destination;
        let key = (local.ip(), local.port());
        if self.udp_binds.contains_key(&key) {
            return;
        }
        let (_hostname, target) = match self.relay.decide(packet) {
            RelayDecision::Relay { hostname, target } => (hostname, target),
            refusal => {
                self.log_gate.log_refusal(&packet.key.destination, &refusal);
                return;
            }
        };
        let make_buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
                vec![0u8; self.socket_buffer_bytes],
            )
        };
        let mut socket = udp::Socket::new(make_buffer(), make_buffer());
        let local_addr = smoltcp_address(local.ip());
        if socket
            .bind(IpListenEndpoint {
                addr: Some(local_addr),
                port: local.port(),
            })
            .is_err()
        {
            return;
        }
        let handle = self.sockets.add(socket);
        self.udp_binds.insert(
            key,
            UdpBind {
                handle,
                local: local_addr,
                target,
                clients: HashMap::new(),
            },
        );
    }

    /// Pump every UDP bind: client datagrams out to their upstreams, upstream
    /// replies back to their clients, then reap idle flows.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn service_udp(&mut self, now_ms: u64) {
        let keys: Vec<(std::net::IpAddr, u16)> = self.udp_binds.keys().copied().collect();
        for key in keys {
            let Some(&UdpBind { handle, local, .. }) = self.udp_binds.get(&key) else {
                continue;
            };

            // Client -> upstream. Copy each datagram out (releasing the socket
            // borrow) before dialing, since dialing mutates the bind map.
            let mut inbound: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
            {
                let socket = self.sockets.get_mut::<udp::Socket>(handle);
                while socket.can_recv() {
                    match socket.recv() {
                        Ok((payload, meta)) => {
                            inbound.push((endpoint_to_socketaddr(meta.endpoint), payload.to_vec()));
                        }
                        Err(_) => break,
                    }
                }
            }
            for (client, payload) in inbound {
                self.udp_forward_upstream(&key, client, &payload, now_ms);
            }

            // Upstream -> client. Drain each client's reply queue, then emit.
            let replies: Vec<(SocketAddr, Vec<Vec<u8>>)> = match self.udp_binds.get(&key) {
                Some(bind) => bind
                    .clients
                    .iter()
                    .map(|(client, flow)| (*client, flow.replies.drain()))
                    .collect(),
                None => continue,
            };
            {
                let socket = self.sockets.get_mut::<udp::Socket>(handle);
                for (client, datagrams) in replies {
                    for datagram in datagrams {
                        let mut meta = udp::UdpMetadata::from(socketaddr_to_endpoint(client));
                        meta.local_address = Some(local);
                        let _ = socket.send_slice(&datagram, meta);
                    }
                }
            }

            self.reap_idle_udp(&key, now_ms);
        }
    }

    /// Send one client datagram upstream, dialing (and starting the reader) the
    /// first time that client is seen on this bind.
    fn udp_forward_upstream(
        &mut self,
        key: &(std::net::IpAddr, u16),
        client: SocketAddr,
        payload: &[u8],
        now_ms: u64,
    ) {
        let known = self
            .udp_binds
            .get(key)
            .is_some_and(|bind| bind.clients.contains_key(&client));
        if !known {
            let Some(target) = self.udp_binds.get(key).map(|bind| bind.target.clone()) else {
                return;
            };
            // UDP dials run inline on the poll thread (no per-flow worker
            // thread exists for the send/first-dial path — see the module
            // doc), so they are NEVER held: a 10 s hold here would freeze
            // every other flow the stack carries. `fake_ip_instant_rst` is a
            // TCP-only setting; UDP always instant-refuses a source-policy
            // refusal, same as every other dial failure.
            self.health.record_udp_relay_flow_opened();
            let dial_started = std::time::Instant::now();
            let datagram = match self.dialer.connect_udp(&target) {
                Ok(datagram) => {
                    self.health.record_udp_dial_ok();
                    datagram
                }
                Err(error) => {
                    let elapsed_ms = dial_started.elapsed().as_millis();
                    if matches!(error, RelayError::SourcePolicyRefused { .. }) {
                        self.health.record_udp_dial_refused();
                        tracing::warn!(
                            target: "nrr::fake-ip",
                            hostname = %target.hostname,
                            route = ?target.route,
                            elapsed_ms = %elapsed_ms,
                            mode = "instant",
                            attempts = 1u32,
                            error = %error,
                            "fake-IP UDP dial refused by source policy — no relay for this client (UDP dials are never held)",
                        );
                    } else {
                        self.health.record_udp_dial_failed();
                    }
                    // Fail CLOSED but not SILENT: the datagram is never relayed,
                    // and the client is told the port is unreachable so it stops
                    // waiting on a protocol timeout and falls back at once. A
                    // refused TCP flow already gets its reset this way.
                    self.send_port_unreachable(*key, client, payload.len());
                    return;
                }
            };
            let upstream: Arc<dyn RelayDatagram> = Arc::from(datagram);
            let replies = UdpReplies::new(Arc::clone(&self.waker));
            let worker = spawn_udp_reader(Arc::clone(&upstream), Arc::clone(&replies));
            if let Some(bind) = self.udp_binds.get_mut(key) {
                bind.clients.insert(
                    client,
                    UdpClientFlow {
                        upstream,
                        replies,
                        worker,
                        last_seen_at: now_ms,
                    },
                );
            }
        }
        let Some(flow) = self
            .udp_binds
            .get_mut(key)
            .and_then(|bind| bind.clients.get_mut(&client))
        else {
            return;
        };
        // Its reader is gone, so nothing would ever carry a reply back.
        if flow.replies.is_dead() {
            self.retire_udp_client(key, client);
            self.send_port_unreachable(*key, client, payload.len());
            return;
        }
        match flow.upstream.send(payload) {
            Ok(_) => flow.last_seen_at = now_ms,
            // The upstream socket is gone (route torn down under the flow, peer
            // hard-refusing). Retiring the client here means the next datagram
            // re-dials rather than being swallowed until the idle reap, and the
            // client learns now instead of at its own timeout.
            Err(_) => {
                self.retire_udp_client(key, client);
                self.send_port_unreachable(*key, client, payload.len());
            }
        }
    }

    /// Drop one client flow from its bind. The next datagram re-dials.
    fn retire_udp_client(&mut self, key: &(std::net::IpAddr, u16), client: SocketAddr) {
        if let Some(retired) = self
            .udp_binds
            .get_mut(key)
            .and_then(|bind| bind.clients.remove(&client))
        {
            retired.replies.mark_dead();
            // Graveyard, not join — same poll-thread rule as the reap.
            self.worker_graveyard.push(retired.worker);
        }
    }

    /// Tell the client the fake endpoint's port is unreachable for a datagram
    /// the relay accepted but could not carry.
    ///
    /// Built and written straight to the device: the datagram was already
    /// consumed by a bound `smoltcp` socket, so the interface's own
    /// port-unreachable path (which fires only when NO socket claims the
    /// endpoint — the refusal case in [`maybe_open_udp`]) never sees it.
    fn send_port_unreachable(
        &mut self,
        fake: (std::net::IpAddr, u16),
        client: SocketAddr,
        payload_len: usize,
    ) {
        let fake = SocketAddr::new(fake.0, fake.1);
        let mut packet = [0u8; UNREACHABLE_MAX_BYTES];
        if let Some(len) = build_port_unreachable(fake, client, payload_len, &mut packet) {
            self.health.record_udp_unreachable_sent();
            self.device.write_client_packet(&packet[..len]);
        }
    }

    /// Drop UDP client flows idle past the window; drop a bind once it has none.
    fn reap_idle_udp(&mut self, key: &(std::net::IpAddr, u16), now_ms: u64) {
        let cutoff = now_ms.saturating_sub(DEFAULT_SESSION_IDLE_MS);
        let mut reaped_workers = Vec::new();
        let empty = if let Some(bind) = self.udp_binds.get_mut(key) {
            let stale: Vec<SocketAddr> = bind
                .clients
                .iter()
                // A flow whose reader died is stale now, whatever the clock says
                // — waiting out the idle window would hold two 64 KiB buffers
                // and a client that can never be answered.
                .filter(|(_, flow)| flow.last_seen_at < cutoff || flow.replies.is_dead())
                .map(|(client, _)| *client)
                .collect();
            for client in stale {
                if let Some(flow) = bind.clients.remove(&client) {
                    flow.replies.mark_dead();
                    // Graveyard, not join — same poll-thread rule as TCP reap.
                    reaped_workers.push(flow.worker);
                }
            }
            bind.clients.is_empty()
        } else {
            false
        };
        self.worker_graveyard.extend(reaped_workers);
        if empty {
            if let Some(bind) = self.udp_binds.remove(key) {
                self.sockets.remove(bind.handle);
            }
        }
    }
}
