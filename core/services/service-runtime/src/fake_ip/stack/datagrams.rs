//! Datagrams: bind, forward, reply, expire.
//!
//! UDP has no handshake and no close, so none of the TCP flow machinery
//! applies: a client is remembered by its (address, port), its replies are
//! fanned back, and it is retired by an idle timer rather than by a FIN.
//! Port-unreachable is the only refusal it can express.
//!
//! Same inherent impl, split across files.

use super::*;
use nrr_platform_api::fake_ip::FlowTransport;

impl FakeIpStack {
    /// Bind a UDP socket for a fresh datagram to an in-scope fake endpoint.
    // `pub(super)`: this split inherent impl is called from a sibling module.
    pub(super) fn maybe_open_udp(&mut self, packet: &ParsedPacket) {
        let local = packet.key.destination;
        let key = (local.ip(), local.port());
        if self.udp_binds.contains_key(&key) {
            return;
        }
        // A bind outlives a step only while it carries a flow, so the bind count
        // is bounded by the flow cap. Refusing here spares a pair of socket
        // buffers per packet, and with no socket bound smoltcp answers
        // port-unreachable itself.
        if self.udp_binds.len() >= self.max_udp_flows {
            self.refuse_udp_at_capacity(self.udp_binds.len());
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
                pending: HashMap::new(),
            },
        );
    }

    /// Pump the UDP binds with work: client datagrams out to their upstreams,
    /// upstream replies back to their clients, then reap idle flows.
    ///
    /// A datagram, a reply, a landed dial or a dead reader marks its bind, as
    /// for TCP; every `FLOW_SWEEP_INTERVAL_MS` all binds are visited anyway,
    /// which is what the idle reap rides on.
    // `pub(super)`: this split inherent impl is called from a sibling module.
    pub(super) fn service_udp(&mut self, now_ms: u64) {
        let sweep_due = now_ms.saturating_sub(self.last_udp_sweep_ms) >= FLOW_SWEEP_INTERVAL_MS;
        let keys: Vec<UdpBindKey> = if sweep_due {
            self.last_udp_sweep_ms = now_ms;
            self.ready_udp.clear();
            self.udp_binds.keys().copied().collect()
        } else {
            self.ready_udp.take()
        };
        for key in keys {
            let Some(&UdpBind { handle, local, .. }) = self.udp_binds.get(&key) else {
                continue;
            };
            self.health.record_udp_bind_serviced();
            self.collect_udp_dials(&key, now_ms);

            // Client -> upstream. Copy each datagram out (releasing the socket
            // borrow) before forwarding, since forwarding mutates the bind map.
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
                self.udp_forward_upstream(&key, client, payload, now_ms);
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
        // Re-armed only well under the cap, so a table hovering at it stays one
        // line in the log.
        if sweep_due && self.udp_capacity_warned {
            let (pending, live) = self.udp_flow_counts();
            if pending + live < self.max_udp_flows / 2 {
                self.udp_capacity_warned = false;
            }
        }
    }

    /// Route one client datagram: straight upstream for a live flow, into the
    /// hold queue while that client's dial runs, or start the dial.
    fn udp_forward_upstream(
        &mut self,
        key: &(std::net::IpAddr, u16),
        client: SocketAddr,
        payload: Vec<u8>,
        now_ms: u64,
    ) {
        let Some(bind) = self.udp_binds.get_mut(key) else {
            return;
        };
        if let Some(pending) = bind.pending.get_mut(&client) {
            // Past the bound the datagram is dropped: the client retransmits.
            if pending.queued.len() < UDP_PENDING_DIAL_QUEUE {
                pending.queued.push_back(payload);
            }
            return;
        }
        if bind.clients.contains_key(&client) {
            self.udp_send_upstream(key, client, &payload, now_ms);
        } else {
            self.start_udp_dial(key, client, payload);
        }
    }

    /// Hand a first-seen client's dial to a worker, holding its datagram.
    ///
    /// Never inline: a dial may resolve the name through the whole resolver
    /// chain first, and this thread carries every other flow on the machine.
    /// UDP dials are never held either — `fake_ip_instant_rst` is TCP-only, so
    /// a source-policy refusal is refused at once like any other failure.
    fn start_udp_dial(
        &mut self,
        key: &(std::net::IpAddr, u16),
        client: SocketAddr,
        payload: Vec<u8>,
    ) {
        let (in_flight, live) = self.udp_flow_counts();
        if in_flight >= MAX_PENDING_UDP_DIALS {
            return;
        }
        if in_flight + live >= self.max_udp_flows {
            self.refuse_udp_at_capacity(in_flight + live);
            self.send_port_unreachable(*key, client, payload.len());
            return;
        }
        let Some(target) = self.udp_binds.get(key).map(|bind| bind.target.clone()) else {
            return;
        };
        // One bind serves every client of a virtual endpoint, and the clients
        // may belong to different users: each is carried for its own.
        let destination = SocketAddr::new(key.0, key.1);
        let owned = self
            .relay
            .for_owner(target, client, destination, Some(FlowTransport::Udp));
        let target = match owned {
            Ok(target) => target,
            Err(refusal) => {
                self.log_gate
                    .log_refusal(&destination, &RelayDecision::from(refusal));
                self.send_port_unreachable(*key, client, payload.len());
                return;
            }
        };
        self.health.record_udp_relay_flow_opened();
        let (book_route, owner) = (target.book_route, target.owner.clone());
        let outcome = Arc::new(Mutex::new(None));
        let submitted = submit_udp_dial(
            &self.dial_pool,
            Arc::clone(&self.dialer),
            target,
            Arc::clone(&outcome),
            Arc::clone(&self.waker),
            (Arc::clone(&self.ready_udp), *key),
        );
        if let Err(refusal) = submitted {
            self.warn_dial_refused(&refusal);
            self.health.record_udp_dial_failed();
            self.send_port_unreachable(*key, client, payload.len());
            return;
        }
        if let Some(bind) = self.udp_binds.get_mut(key) {
            bind.pending.insert(
                client,
                PendingUdpDial {
                    outcome,
                    book_route,
                    owner,
                    first_payload_len: payload.len(),
                    queued: VecDeque::from([payload]),
                    started_at: std::time::Instant::now(),
                },
            );
        }
    }

    /// Adopt every dial on this bind that has landed: open the flow and flush
    /// its held datagrams, or tell the client the port is unreachable.
    fn collect_udp_dials(&mut self, key: &(std::net::IpAddr, u16), now_ms: u64) {
        let landed: Vec<(SocketAddr, PendingUdpDial, UdpDialOutcome)> = {
            let Some(bind) = self.udp_binds.get_mut(key) else {
                return;
            };
            if bind.pending.is_empty() {
                return;
            }
            let ready: Vec<(SocketAddr, UdpDialOutcome)> = bind
                .pending
                .iter()
                .filter_map(|(client, pending)| {
                    guard(&pending.outcome)
                        .take()
                        .map(|outcome| (*client, outcome))
                })
                .collect();
            ready
                .into_iter()
                .filter_map(|(client, outcome)| {
                    bind.pending
                        .remove(&client)
                        .map(|pending| (client, pending, outcome))
                })
                .collect()
        };
        for (client, pending, outcome) in landed {
            let datagram = match outcome {
                Ok(datagram) => {
                    self.health.record_udp_dial_ok();
                    datagram
                }
                Err(error) => {
                    self.record_udp_dial_failure(key, &error, pending.started_at);
                    // Fail CLOSED but not SILENT: the client learns the port is
                    // unreachable and falls back at once instead of waiting out
                    // a protocol timeout — the UDP twin of a refused flow's RST.
                    self.send_port_unreachable(*key, client, pending.first_payload_len);
                    continue;
                }
            };
            let upstream: Arc<dyn RelayDatagram> = Arc::from(datagram);
            let replies = UdpReplies::for_bind(
                Arc::clone(&self.waker),
                Arc::clone(&self.ready_udp),
                *key,
                Arc::clone(&self.health),
            );
            // No reader, no replies: the flow fails here, like a dial that
            // never landed. The upstream socket closes with `upstream`.
            let worker = match spawn_udp_reader(Arc::clone(&upstream), Arc::clone(&replies)) {
                Ok(worker) => worker,
                Err(_) => {
                    self.health.record_worker_spawn_failed();
                    self.send_port_unreachable(*key, client, pending.first_payload_len);
                    continue;
                }
            };
            let Some(bind) = self.udp_binds.get_mut(key) else {
                return;
            };
            bind.clients.insert(
                client,
                UdpClientFlow {
                    upstream,
                    replies,
                    worker,
                    last_seen_at: now_ms,
                    last_payload_len: pending.first_payload_len,
                    book_route: pending.book_route,
                    owner: pending.owner.clone(),
                },
            );
            for datagram in pending.queued {
                if !self.udp_send_upstream(key, client, &datagram, now_ms) {
                    break;
                }
            }
        }
    }

    /// Dialing and live UDP client flows across every bind.
    fn udp_flow_counts(&self) -> (usize, usize) {
        self.udp_binds
            .values()
            .fold((0, 0), |(pending, live), bind| {
                (pending + bind.pending.len(), live + bind.clients.len())
            })
    }

    /// Counted per refusal, logged once per episode: at the cap refusals come
    /// as fast as clients retransmit.
    fn refuse_udp_at_capacity(&mut self, active: usize) {
        self.health.record_udp_flow_refused_at_capacity();
        if self.udp_capacity_warned {
            return;
        }
        self.udp_capacity_warned = true;
        tracing::warn!(
            target: "nrr::fake-ip",
            msg_key = "fakeip-udp-flow-capacity-reached",
            active,
            cap = self.max_udp_flows,
            "fake-IP is carrying its maximum number of UDP flows — new clients are told port-unreachable until some go idle",
        );
    }

    fn record_udp_dial_failure(
        &self,
        key: &(std::net::IpAddr, u16),
        error: &RelayError,
        started_at: std::time::Instant,
    ) {
        if !matches!(error, RelayError::SourcePolicyRefused { .. }) {
            self.health.record_udp_dial_failed();
            return;
        }
        self.health.record_udp_dial_refused();
        let Some(target) = self.udp_binds.get(key).map(|bind| &bind.target) else {
            return;
        };
        tracing::warn!(
            target: "nrr::fake-ip",
            msg_key = "fakeip-udp-dial-policy-refused",
            hostname = %target.hostname,
            route = ?target.route,
            elapsed_ms = %started_at.elapsed().as_millis(),
            mode = "instant",
            attempts = 1u32,
            error = %error,
            "fake-IP UDP dial refused by source policy — no relay for this client (UDP dials are never held)",
        );
    }

    /// Send one datagram on a live client flow. Returns whether the flow is
    /// still usable; a dead one has been retired and the client told.
    fn udp_send_upstream(
        &mut self,
        key: &(std::net::IpAddr, u16),
        client: SocketAddr,
        payload: &[u8],
        now_ms: u64,
    ) -> bool {
        let Some(flow) = self
            .udp_binds
            .get_mut(key)
            .and_then(|bind| bind.clients.get_mut(&client))
        else {
            return false;
        };
        // Its reader is gone, so nothing would ever carry a reply back.
        if flow.replies.is_dead() {
            self.retire_udp_client(key, client);
            self.send_port_unreachable(*key, client, payload.len());
            return false;
        }
        match flow.upstream.send(payload) {
            Ok(_) => {
                flow.last_seen_at = now_ms;
                flow.last_payload_len = payload.len();
                true
            }
            // The upstream socket is gone (route torn down under the flow, peer
            // hard-refusing). Retiring the client here means the next datagram
            // re-dials rather than being swallowed until the idle reap, and the
            // client learns now instead of at its own timeout.
            Err(_) => {
                self.retire_udp_client(key, client);
                self.send_port_unreachable(*key, client, payload.len());
                false
            }
        }
    }

    /// Retire every UDP flow whose route the books no longer give, live or
    /// still dialling. A bind the routing user's book moved goes whole: its
    /// target was decided by that book, and the next datagram binds afresh
    /// under the new one, where a block is answered port-unreachable.
    // `pub(super)`: this split inherent impl is called from a sibling module.
    pub(super) fn recheck_udp_policy(&mut self) {
        let mut stale_binds = Vec::new();
        let mut stale_clients = Vec::new();
        {
            let mut books = BookRoutes::new(&self.relay);
            for (key, bind) in &mut self.udp_binds {
                let hostname = bind.target.hostname.as_str();
                // The in-tunnel rescue carries a literal address no book names.
                if hostname.parse::<std::net::IpAddr>().is_ok() {
                    continue;
                }
                if books.route(None, hostname) != bind.target.book_route {
                    stale_binds.push(*key);
                    continue;
                }
                let mut holds = |route: Option<RouteRole>, owner: Option<&str>| {
                    owner.is_none() || books.route(owner, hostname) == route
                };
                stale_clients.extend(
                    bind.clients
                        .iter()
                        .filter(|(_, flow)| !holds(flow.book_route, flow.owner.as_deref()))
                        .map(|(client, _)| (*key, *client)),
                );
                bind.pending
                    .retain(|_, pending| holds(pending.book_route, pending.owner.as_deref()));
            }
        }
        for (key, client) in stale_clients {
            self.retire_udp_client(&key, client);
        }
        for key in stale_binds {
            self.drop_udp_bind(&key);
        }
    }

    /// Remove a bind with every client and dial on it.
    fn drop_udp_bind(&mut self, key: &(std::net::IpAddr, u16)) {
        let Some(bind) = self.udp_binds.remove(key) else {
            return;
        };
        self.sockets.remove(bind.handle);
        for (_, flow) in bind.clients {
            flow.replies.mark_dead();
            // Graveyard, not join — same poll-thread rule as the reap.
            self.worker_graveyard.push(flow.worker);
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
        let mut refused = Vec::new();
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
                    // A dead reader is the server refusing (or the path
                    // failing): the client hears it now, not at its own timer.
                    if flow.replies.is_dead() {
                        refused.push((client, flow.last_payload_len));
                    }
                    flow.replies.mark_dead();
                    // Graveyard, not join — same poll-thread rule as TCP reap.
                    reaped_workers.push(flow.worker);
                }
            }
            // A dial is bounded by its own timeouts; this only guards against
            // a dialer that never returns pinning the bind forever.
            bind.pending.retain(|_, pending| {
                pending.started_at.elapsed()
                    < std::time::Duration::from_millis(DEFAULT_SESSION_IDLE_MS)
            });
            bind.clients.is_empty() && bind.pending.is_empty()
        } else {
            false
        };
        self.worker_graveyard.extend(reaped_workers);
        for (client, payload_len) in refused {
            self.send_port_unreachable(*key, client, payload_len);
        }
        if empty {
            if let Some(bind) = self.udp_binds.remove(key) {
                self.sockets.remove(bind.handle);
            }
        }
    }
}
