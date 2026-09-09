//! Opening a TCP flow and pumping it in both directions.
//!
//! A new SYN is classified before `smoltcp` sees it, so the socket exists
//! by the time the handshake needs one; after that the flow is spliced to
//! its upstream and serviced until both halves close. The capacity check
//! lives here too — refusing a flow is part of opening one.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

impl FakeIpStack {
    /// Open a flow for a fresh TCP SYN to an in-scope fake address.
    ///
    /// The client handshake is answered immediately; the upstream dial runs on
    /// its own worker thread. A dial can block for seconds (dead host, downed
    /// route), and the poll thread is shared by every flow — one doomed dial
    /// must never stall the stack for everyone else. A failed dial surfaces to
    /// the client as an RST right after the handshake instead of a stall.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn maybe_open_flow(&mut self, packet: &ParsedPacket, now_ms: u64) {
        if packet.key.protocol != FlowProtocol::Tcp || !packet.is_connection_open {
            return;
        }
        if self.flows.contains_key(&packet.key) {
            return;
        }
        if self.flows.len() >= self.max_flows {
            self.health.record_tcp_flow_refused_at_capacity();
            self.warn_at_flow_capacity();
            return;
        }
        let (hostname, target) = match self.relay.decide(packet) {
            RelayDecision::Relay { hostname, target } => (hostname, target),
            // Anything else (not ours, unmapped, out of scope, no upstream) gets
            // no socket, so smoltcp answers the SYN with a reset — the flow fails
            // closed instead of leaking to a guess.
            refusal => {
                self.log_gate.log_refusal(&packet.key.destination, &refusal);
                return;
            }
        };
        // Notify the observer (VPN self-heal) with the client's own endpoint and
        // the fake destination it dialed. Must be prompt — the production
        // observer only enqueues.
        self.flow_observer
            .on_flow_opened(packet.key.source, packet.key.destination, &hostname);

        let rx = tcp::SocketBuffer::new(vec![0u8; self.socket_buffer_bytes]);
        let tx = tcp::SocketBuffer::new(vec![0u8; self.socket_buffer_bytes]);
        let mut socket = tcp::Socket::new(rx, tx);
        // smoltcp's own liveness pair: probe a quiet peer, drop it if the probes
        // go unanswered. Without them a client that disappeared without FIN
        // holds its buffers and workers for the life of the stack.
        socket.set_keep_alive(Some(TCP_FLOW_KEEP_ALIVE.into()));
        socket.set_timeout(Some(TCP_FLOW_IDLE.into()));
        let listen = IpListenEndpoint {
            addr: Some(smoltcp_address(packet.key.destination.ip())),
            port: packet.key.destination.port(),
        };
        if socket.listen(listen).is_err() {
            return;
        }
        let handle = self.sockets.add(socket);

        self.health.record_tcp_relay_flow_opened();
        let shared =
            FlowShared::for_flow(Arc::clone(&self.waker), Arc::clone(&self.ready), packet.key);
        spawn_dial_worker(
            Arc::clone(&shared),
            Arc::clone(&self.dialer),
            target,
            Arc::clone(&self.log_gate),
            Arc::clone(&self.health),
            Arc::clone(&self.instant_rst),
        );
        self.ready.mark(packet.key);
        self.flows.insert(
            packet.key,
            FlowConn {
                handle,
                shared,
                client_close_sent: false,
                abort_sent: false,
            },
        );
        let _ = now_ms;
    }

    /// Move bytes between the sockets with work and their upstreams, then reap
    /// finished flows.
    ///
    /// Only the flows something happened to are visited — an inbound packet or
    /// a worker marks them (see `ReadyFlows`). Every `FLOW_SWEEP_INTERVAL_MS`
    /// the whole map is visited regardless, which is what makes the marking an
    /// optimisation rather than a correctness dependency: `smoltcp` can close a
    /// flow on its own idle or keep-alive timeout, and nobody marks that.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn service_flows(&mut self, now_ms: u64) {
        let sweep_due = now_ms.saturating_sub(self.last_flow_sweep_ms) >= FLOW_SWEEP_INTERVAL_MS;
        let keys: Vec<FlowKey> = if sweep_due {
            self.last_flow_sweep_ms = now_ms;
            self.ready.clear();
            self.flows.keys().copied().collect()
        } else {
            self.ready.take()
        };

        let mut finished = Vec::new();
        // Flows whose next move needs another step: the RST queued below is only
        // dispatched by the following poll, and no packet or worker will ask for
        // that step.
        let mut revisit = Vec::new();
        for key in keys {
            let Some(flow) = self.flows.get_mut(&key) else {
                continue;
            };
            self.health.record_flow_serviced();
            let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);

            // The dial worker gave up: reset the client instead of stalling it.
            // The reap waits one poll so the queued RST is actually dispatched;
            // a retransmission after removal is reset by the interface anyway.
            if flow.shared.dial_has_failed() && !flow.abort_sent {
                socket.abort();
                flow.abort_sent = true;
                revisit.push(key);
                continue;
            }
            if flow.abort_sent {
                flow.shared.mark_dead();
                finished.push(key);
                continue;
            }

            // Client -> upstream — only once the upstream exists. While the
            // dial is in flight the bytes stay in the socket buffer, so the
            // client's own TCP window backpressures instead of an unbounded
            // queue growing against a slow dial.
            while flow.shared.dial_is_done()
                && socket.can_recv()
                && flow.shared.to_upstream_len() < FLOW_QUEUE_HIGH_WATER_BYTES
            {
                let mut chunk = [0u8; PUMP_CHUNK_BYTES];
                match socket.recv_slice(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => flow.shared.push_to_upstream(&chunk[..n]),
                }
            }
            if client_fin_may_propagate(flow.shared.dial_is_done(), socket.state()) {
                flow.shared.signal_client_fin();
            }

            // Upstream -> client.
            while socket.can_send() {
                let chunk = flow.shared.take_from_upstream(PUMP_CHUNK_BYTES);
                if chunk.is_empty() {
                    break;
                }
                match socket.send_slice(&chunk) {
                    Ok(sent) if sent < chunk.len() => {
                        flow.shared.return_from_upstream(&chunk[sent..]);
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        flow.shared.return_from_upstream(&chunk);
                        break;
                    }
                }
            }
            // Upstream broke off: drain what did arrive, then reset — the
            // client must not read a truncated body as a complete one.
            if flow.shared.upstream_was_reset()
                && flow.shared.upstream_queue_is_empty()
                && !flow.abort_sent
            {
                socket.abort();
                flow.abort_sent = true;
                revisit.push(key);
                continue;
            }
            // Upstream is done and drained: mirror its close to the client once.
            if flow.shared.upstream_eof.load(Ordering::SeqCst)
                && flow.shared.upstream_queue_is_empty()
                && !flow.client_close_sent
                && socket.may_send()
            {
                socket.close();
                flow.client_close_sent = true;
            }

            if socket.state() == tcp::State::Closed {
                flow.shared.mark_dead();
                finished.push(key);
            }
        }

        for key in revisit {
            self.ready.mark(key);
            self.waker.wake();
        }

        for key in finished {
            if let Some(flow) = self.flows.remove(&key) {
                self.sockets.remove(flow.handle);
                flow.shared.mark_dead();
                // Handles go to the graveyard, never joined here: a worker
                // blocked on a stalled upstream would hold this join — and
                // with it the poll thread, i.e. the entire datapath.
                self.worker_graveyard.extend(flow.shared.take_workers());
            }
        }
    }
}
