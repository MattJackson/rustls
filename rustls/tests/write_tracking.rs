//! Actual encrypted output prefixes, including failures after partial writes.

use std::io::{self, IoSlice, Write};

use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, cipher_suite};
use rustls::{ServerConnection, SupportedCipherSuite, WriteTrackingFault, WriteTrackingLimits};
use rustls_test::{
    KeyType, do_handshake, make_client_config_with_versions, make_pair_for_configs,
    make_server_config_with_versions,
};

fn established(suite: SupportedCipherSuite, records: usize) -> ServerConnection {
    let provider = CryptoProvider {
        cipher_suites: vec![suite],
        ..aws_lc_rs::default_provider()
    };
    let versions = &[suite.version()];
    let (mut client, mut server) = make_pair_for_configs(
        make_client_config_with_versions(KeyType::Rsa2048, versions, &provider),
        make_server_config_with_versions(KeyType::Rsa2048, versions, &provider),
    );
    do_handshake(&mut client, &mut server);
    while server.wants_write() {
        server.write_tls(&mut io::sink()).unwrap();
    }
    server
        .enable_write_tracking(WriteTrackingLimits {
            max_pending_records: records,
        })
        .unwrap();
    server
}

struct Prefix {
    limit: usize,
    bytes: Vec<u8>,
}

impl Write for Prefix {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_vectored(&[IoSlice::new(bytes)])
    }

    fn write_vectored(&mut self, slices: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut left = self.limit;
        let before = self.bytes.len();
        for slice in slices {
            let take = slice.len().min(left);
            self.bytes.extend_from_slice(&slice[..take]);
            left -= take;
        }
        Ok(self.bytes.len() - before)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn every_actual_ciphertext_prefix_has_exact_application_provenance() {
    for (suite, prefix, suffix) in [
        (cipher_suite::TLS13_AES_128_GCM_SHA256, 5, 17),
        (cipher_suite::TLS13_AES_256_GCM_SHA384, 5, 17),
        (cipher_suite::TLS13_CHACHA20_POLY1305_SHA256, 5, 17),
        (cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 13, 16),
        (cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 13, 16),
        (cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 5, 16),
    ] {
        let mut server = established(suite, 4);
        let payload = b"head-body-control";
        assert_eq!(server.writer().write(payload).unwrap(), payload.len());
        let initial = server.write_progress().unwrap();
        assert_eq!(initial.accepted_plaintext, payload.len() as u64);
        assert_eq!(initial.written_plaintext, 0);
        assert_eq!(initial.complete_records_plaintext, 0);
        let total = prefix + payload.len() + suffix;
        let mut raw = Prefix { limit: 1, bytes: Vec::new() };
        for end in 1..=total {
            assert_eq!(server.write_tls(&mut raw).unwrap(), 1);
            let progress = server.write_progress().unwrap();
            assert_eq!(progress.written_plaintext, end.saturating_sub(prefix).min(payload.len()) as u64);
            assert_eq!(progress.complete_records_plaintext, if end == total { payload.len() as u64 } else { 0 });
            assert_eq!(progress.fault, None);
        }
        assert_eq!(raw.bytes.len(), total);
        assert!(!server.wants_write());
        server.send_close_notify();
        server.write_tls(&mut io::sink()).unwrap();
        assert_eq!(server.write_progress().unwrap().written_plaintext, payload.len() as u64);
    }
}

#[test]
fn nonempty_zero_preserves_prior_progress_and_poison_is_sticky() {
    let mut server = established(cipher_suite::TLS13_AES_128_GCM_SHA256, 1);
    server.writer().write_all(b"payload").unwrap();
    let mut raw = Prefix { limit: 6, bytes: Vec::new() };
    assert_eq!(server.write_tls(&mut raw).unwrap(), 6);
    assert_eq!(server.write_progress().unwrap().written_plaintext, 1);
    raw.limit = 0;
    assert_eq!(server.write_tls(&mut raw).unwrap_err().kind(), io::ErrorKind::WriteZero);
    let progress = server.write_progress().unwrap();
    assert_eq!(progress.accepted_plaintext, 7);
    assert_eq!(progress.written_plaintext, 1);
    assert_eq!(progress.complete_records_plaintext, 0);
    assert_eq!(progress.fault, Some(WriteTrackingFault::WriteZero));
    assert!(server.writer().write(b"later").is_err());
    raw.limit = usize::MAX;
    assert!(server.write_tls(&mut raw).is_err());
    assert_eq!(raw.bytes.len(), 6);
}

#[test]
fn descriptor_capacity_backpressures_until_full_record_retires() {
    let mut server = established(cipher_suite::TLS13_AES_128_GCM_SHA256, 1);
    assert_eq!(server.writer().write(b"first").unwrap(), 5);
    assert_eq!(server.writer().write(b"second").unwrap(), 0);
    let mut raw = Prefix { limit: 10, bytes: Vec::new() };
    server.write_tls(&mut raw).unwrap();
    assert_eq!(server.write_progress().unwrap().written_plaintext, 5);
    assert_eq!(server.writer().write(b"second").unwrap(), 0);
    raw.limit = usize::MAX;
    server.write_tls(&mut raw).unwrap();
    assert_eq!(server.write_progress().unwrap().complete_records_plaintext, 5);
    assert_eq!(server.writer().write(b"second").unwrap(), 6);
    assert_eq!(server.write_progress().unwrap().accepted_plaintext, 11);
}

#[test]
fn enum_drain_cannot_bypass_tracking_and_empty_zero_is_not_failure() {
    let mut server = established(cipher_suite::TLS13_AES_128_GCM_SHA256, 1);
    let mut zero = Prefix { limit: 0, bytes: Vec::new() };
    assert_eq!(server.write_tls(&mut zero).unwrap(), 0);
    assert_eq!(server.write_progress().unwrap().fault, None);
    server.writer().write_all(b"x").unwrap();
    let mut server = rustls::Connection::Server(server);
    assert_eq!(server.write_tls(&mut zero).unwrap_err().kind(), io::ErrorKind::WriteZero);
    assert_eq!(server.write_progress().unwrap().fault, Some(WriteTrackingFault::WriteZero));
}

#[test]
fn late_enable_is_refused_even_after_application_record_is_drained() {
    let provider = aws_lc_rs::default_provider();
    let (mut client, mut server) = rustls_test::make_pair(KeyType::Rsa2048, &provider);
    do_handshake(&mut client, &mut server);
    server.writer().write_all(b"untracked").unwrap();
    while server.wants_write() {
        server.write_tls(&mut io::sink()).unwrap();
    }
    assert!(server.enable_write_tracking(WriteTrackingLimits { max_pending_records: 4 }).is_err());
}
