use super::*;

const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 78, 25);
const HOST: &str = "gateway.corp.example";
const LDAP: &str = "_ldap._tcp.dc._msdcs.corp.example";
const KERBEROS: &str = "_kerberos._tcp.corp.example";
const SRV: u16 = 33;

fn srv_answer(q: &[u8], _: &str) -> Option<Vec<u8>> {
    let parsed = parse_question(q)?;
    let mut reply = build_error_response(q, RCODE_NOERROR)?;
    reply[6..8].copy_from_slice(&1u16.to_be_bytes());
    reply.extend_from_slice(&[0xC0, 0x0C]);
    reply.extend_from_slice(&SRV.to_be_bytes());
    reply.extend_from_slice(&1u16.to_be_bytes());
    reply.extend_from_slice(&60u32.to_be_bytes());
    let target = query("dc.corp.example", QTYPE_A);
    let target_name = &target[12..target.len() - 4];
    reply.extend_from_slice(&((6 + target_name.len()) as u16).to_be_bytes());
    reply.extend_from_slice(&[0, 0, 0, 100]);
    let port: u16 = if parsed.qname.starts_with("_kerberos.") {
        88
    } else {
        389
    };
    reply.extend_from_slice(&port.to_be_bytes());
    reply.extend_from_slice(target_name);
    Some(reply)
}

#[test]
fn public_nodata_must_not_hide_ldap_or_kerberos_domain_discovery() {
    for name in [LDAP, KERBEROS] {
        for transport in [Transport::Udp, Transport::Tcp] {
            let (public, private) = match transport {
                Transport::Udp => (fake_resolver(nodata), fake_resolver(srv_answer)),
                Transport::Tcp => (tcp_resolver(nodata), tcp_resolver(srv_answer)),
            };
            let l = split_listener(public, private.port());
            let q = query(name, SRV);
            assert_eq!(
                l.forward_within(&q, Duration::from_secs(3), transport),
                srv_answer(&q, name),
                "the stub must receive the corporate SRV answer over {transport:?}"
            );
        }
    }
}

#[test]
fn a_private_srv_error_or_empty_reply_must_not_hide_the_next_resolver() {
    let l = two_private_resolvers_listener(Duration::from_secs(1));
    let q = query(LDAP, SRV);
    for rcode in [RCODE_NOERROR, RCODE_SERVFAIL, RCODE_NXDOMAIN] {
        let mut asked = Vec::new();
        let reply = l.ask_private_resolvers_via(
            &q,
            "192.0.2.1:53".parse().expect("public resolver"),
            Duration::from_secs(3),
            Instant::now,
            |target, _| {
                asked.push(target.ip());
                if target.ip() == IpAddr::V4(FIRST_RESOLVER) {
                    build_negative_response(&q, rcode, 60)
                } else {
                    srv_answer(&q, LDAP)
                }
            },
        );
        assert_eq!(reply, srv_answer(&q, LDAP));
        assert_eq!(asked.len(), 2, "rcode {rcode} is not a service location");
    }
}

#[test]
fn a_private_srv_reply_must_match_the_question_and_be_complete() {
    let l = two_private_resolvers_listener(Duration::from_secs(1));
    let q = query(LDAP, SRV);
    let mut truncated = srv_answer(&q, LDAP).expect("SRV");
    truncated[2] |= 0x02;
    let wrong = srv_answer(&query(KERBEROS, SRV), KERBEROS).expect("other SRV");
    for first in [truncated, wrong, vec![0x12, 0x34, 0x81]] {
        let reply = l.ask_private_resolvers_via(
            &q,
            "192.0.2.1:53".parse().expect("public resolver"),
            Duration::from_secs(3),
            Instant::now,
            |target, _| {
                if target.ip() == IpAddr::V4(FIRST_RESOLVER) {
                    Some(first.clone())
                } else {
                    srv_answer(&q, LDAP)
                }
            },
        );
        assert_eq!(reply, srv_answer(&q, LDAP));
    }
}

#[test]
fn a_secondary_service_name_stays_withheld_when_the_guard_blocks() {
    let l = listener(&[LDAP], Err(ResolveError::Unavailable("offline".into())))
        .with_leak_guard_posture(Arc::new(|| true))
        .with_private_resolvers(Arc::new(|_| panic!("a protected SRV query must not forward")));
    match l.answer_query(&query(LDAP, SRV)) {
        ListenerAction::Respond(reply) => assert_eq!(reply[3] & 0x0F, RCODE_SERVFAIL),
        other => panic!("must withhold the secondary SRV query, got {other:?}"),
    }
}

#[test]
fn ordinary_empty_txt_answers_do_not_trigger_service_discovery_recovery() {
    let public = fake_resolver(nodata);
    let l = split_listener(public, 53).with_private_resolvers(Arc::new(|_| {
        panic!("the service-discovery fix must not retry unrelated query types")
    }));
    let q = query(HOST, 16);
    assert_eq!(
        l.forward_within(&q, Duration::from_secs(3), Transport::Udp),
        nodata(&q, HOST)
    );
}

fn nodata(q: &[u8], _: &str) -> Option<Vec<u8>> {
    build_negative_response(q, RCODE_NOERROR, 60)
}

fn corporate_answer(q: &[u8], _: &str) -> Option<Vec<u8>> {
    build_a_response(q, &[GATEWAY], 60)
}

fn split_listener(public: SocketAddr, private_port: u16) -> DnsInterceptListener {
    DnsInterceptListener::new(
        Arc::new(Oracle(Vec::new())),
        Arc::new(Upstream(Ok(resolved(&[])))),
        Arc::new(NoopSink),
        Arc::new(OkReconciler),
        public,
        Duration::from_millis(150),
        Duration::from_secs(1),
    )
    .with_private_resolvers(Arc::new(|_| vec![Ipv4Addr::LOCALHOST]))
    .with_resolver_port(private_port)
}

fn assert_gateway(reply: &[u8]) {
    match parse_address_response(0x1234, HOST, QTYPE_A, reply) {
        AddressResponseOutcome::Answers { addresses, .. } => {
            assert_eq!(addresses, vec![IpAddr::V4(GATEWAY)]);
        }
        other => panic!("corporate gateway must resolve, got {other:?}"),
    }
}

#[test]
fn public_nodata_does_not_hide_a_corporate_rdp_gateway() {
    let public = fake_resolver(nodata);
    let private = fake_resolver(corporate_answer);
    let l = split_listener(public, private.port());
    let reply = l
        .forward_within(
            &query(HOST, QTYPE_A),
            Duration::from_secs(3),
            Transport::Udp,
        )
        .expect("DNS reply");
    assert_gateway(&reply);
}

#[test]
fn an_empty_or_failed_private_answer_does_not_hide_the_next_resolvers_address() {
    let l = two_private_resolvers_listener(Duration::from_secs(1));
    for rcode in [RCODE_NOERROR, RCODE_SERVFAIL] {
        let (reply, asked) = ask_on_a_manual_clock(&l, Duration::from_secs(3), |server, _, q| {
            let reply = if server == FIRST_RESOLVER {
                build_negative_response(q, rcode, 60)
            } else {
                build_a_response(q, &[GATEWAY], 60)
            };
            (Duration::ZERO, reply)
        });
        assert_eq!(asked.len(), 2, "rcode {rcode} did not supply an address");
        let reply = reply.expect("second private resolver knows the host");
        assert!(matches!(
            parse_address_response(0x1234, "host.corp.example", QTYPE_A, &reply),
            AddressResponseOutcome::Answers { addresses, .. }
                if addresses == vec![IpAddr::V4(GATEWAY)]
        ));
    }
}

#[test]
fn ordinary_aaaa_nodata_does_not_consult_private_resolvers() {
    let public = fake_resolver(nodata);
    let l = split_listener(public, 53).with_private_resolvers(Arc::new(|_| {
        panic!("AAAA NODATA is not evidence of a missing corporate A answer")
    }));
    let q = query(HOST, QTYPE_AAAA);
    assert_eq!(
        l.forward_within(&q, Duration::from_secs(3), Transport::Udp),
        nodata(&q, HOST)
    );
}

#[test]
fn an_answered_or_truncated_a_query_does_not_trigger_private_recovery() {
    for answer in [
        corporate_answer as fn(&[u8], &str) -> Option<Vec<u8>>,
        |q, _| {
            let mut reply = build_negative_response(q, RCODE_NOERROR, 60)?;
            reply[2] |= 0x02;
            Some(reply)
        },
    ] {
        let public = fake_resolver(answer);
        let l = split_listener(public, 53).with_private_resolvers(Arc::new(|_| {
            panic!("an answered or truncated query must keep its original response")
        }));
        let q = query(HOST, QTYPE_A);
        assert_eq!(
            l.forward_within(&q, Duration::from_secs(3), Transport::Udp),
            answer(&q, HOST)
        );
    }
}

/// One bounded fake TCP exchange, with no real DNS or machine configuration.
fn tcp_resolver(answer: fn(&[u8], &str) -> Option<Vec<u8>>) -> SocketAddr {
    let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("TCP resolver");
    let addr = socket.local_addr().expect("TCP address");
    socket.set_nonblocking(true).expect("nonblocking accept");
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match socket.accept() {
                Ok((mut stream, _)) => {
                    let mut bounded = DeadlineStream::new(
                        &mut stream,
                        Duration::from_secs(2),
                        Duration::from_secs(2),
                    );
                    if let Ok(Some(q)) = crate::dns_wire::read_tcp_message(&mut bounded, 4096) {
                        if let Some(reply) = answer(&q, HOST) {
                            let _ = crate::dns_wire::write_tcp_message(&mut bounded, &reply);
                        }
                    }
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    addr
}

#[test]
fn a_tcp_nodata_retry_reaches_a_tcp_only_corporate_resolver() {
    let public = tcp_resolver(nodata);
    let private = tcp_resolver(corporate_answer);
    let l = split_listener(public, private.port());
    let reply = l
        .forward_within(
            &query(HOST, QTYPE_A),
            Duration::from_secs(3),
            Transport::Tcp,
        )
        .expect("TCP DNS reply");
    assert_gateway(&reply);
}

#[test]
fn a_secondary_rule_cannot_use_private_dns_to_escape_the_leak_guard() {
    let l = listener(&[HOST], Err(ResolveError::Unavailable("offline".into())))
        .with_leak_guard_posture(Arc::new(|| true))
        .with_private_resolvers(Arc::new(|_| panic!("a withheld rule must never forward")));
    match l.answer_query(&query(HOST, QTYPE_A)) {
        ListenerAction::Respond(reply) => assert_eq!(reply[3] & 0x0F, RCODE_SERVFAIL),
        other => panic!("must withhold the secondary rule, got {other:?}"),
    }
}
