use std::fs;
use std::path::Path;

#[test]
fn test_spec_domain_matching_vectors() {
    let test_file = Path::new("../spec/test-data/test_cases.json");
    let content = if test_file.exists() {
        fs::read_to_string(test_file).unwrap()
    } else {
        fs::read_to_string("spec/test-data/test_cases.json").unwrap()
    };

    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let rules: Vec<String> = parsed["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let mut store = adblock_engine_rs::rules::RuleStore::new();
    store.add(&rules);

    for case in parsed["cases"].as_array().unwrap() {
        let query = case["query"].as_str().unwrap();
        let expected_blocked = case["expected_blocked"].as_bool().unwrap();
        let desc = case["description"].as_str().unwrap();

        let matched = store.check(query).is_some();
        assert_eq!(
            matched, expected_blocked,
            "Failed spec case: '{}' ({}) expected_blocked: {}, actual: {}",
            query, desc, expected_blocked, matched
        );
    }
}

#[test]
fn test_spec_packet_hex_vectors() {
    let packet_file = Path::new("../spec/test-data/packets.json");
    let content = if packet_file.exists() {
        fs::read_to_string(packet_file).unwrap()
    } else {
        fs::read_to_string("spec/test-data/packets.json").unwrap()
    };

    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    // 1. DNS query ad
    let dns_ad = &parsed["dns_query_ad"];
    let raw_dns_ad = hex::decode(dns_ad["hex"].as_str().unwrap()).unwrap();
    let info_dns = adblock_engine_rs::packet::inspect_packet(&raw_dns_ad).unwrap();
    assert_eq!(info_dns.protocol, adblock_engine_rs::packet::PacketProtocol::Dns);
    assert_eq!(info_dns.domain.as_deref(), Some(dns_ad["expected_domain"].as_str().unwrap()));

    let nxdomain = adblock_engine_rs::packet::dns::build_dns_nxdomain(&raw_dns_ad, info_dns.is_ipv6).unwrap();
    assert!(!nxdomain.is_empty());

    // 2. TLS ClientHello ad
    let tls_ad = &parsed["tls_clienthello_ad"];
    let raw_tls_ad = hex::decode(tls_ad["hex"].as_str().unwrap()).unwrap();
    let info_tls = adblock_engine_rs::packet::inspect_packet(&raw_tls_ad).unwrap();
    assert_eq!(info_tls.protocol, adblock_engine_rs::packet::PacketProtocol::Tls);
    assert_eq!(info_tls.domain.as_deref(), Some(tls_ad["expected_domain"].as_str().unwrap()));

    let rst = adblock_engine_rs::packet::tls::build_tcp_rst(&raw_tls_ad, info_tls.is_ipv6).unwrap();
    assert_eq!(rst.len(), 40); // 20 IP + 20 TCP

    // 3. QUIC packet
    let quic = &parsed["quic_packet"];
    let raw_quic = hex::decode(quic["hex"].as_str().unwrap()).unwrap();
    let info_quic = adblock_engine_rs::packet::inspect_packet(&raw_quic).unwrap();
    assert_eq!(info_quic.protocol, adblock_engine_rs::packet::PacketProtocol::Quic);
    assert_eq!(info_quic.domain.as_deref(), Some(quic["expected_domain"].as_str().unwrap()));
}
