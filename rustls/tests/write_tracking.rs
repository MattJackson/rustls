//! Actual encrypted output prefixes, including failures after partial writes.

use std::io::{self, IoSlice, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, cipher_suite};
use rustls::crypto::cipher::{
    AeadKey, Iv, MessageDecrypter, MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::{ServerConnection, SupportedCipherSuite, WriteTrackingFault, WriteTrackingLimits};
use rustls_test::{
    KeyType, do_handshake, make_client_config_with_versions, make_pair_for_configs,
    make_server_config_with_versions,
};

fn established(suite: SupportedCipherSuite, records: usize) -> ServerConnection {
    established_pair(suite, records).1
}

fn established_pair(
    suite: SupportedCipherSuite,
    records: usize,
) -> (rustls::ClientConnection, ServerConnection) {
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
        server
            .write_tls(&mut io::sink())
            .unwrap();
    }
    server
        .enable_write_tracking(WriteTrackingLimits {
            max_pending_records: records,
        })
        .unwrap();
    (client, server)
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
            self.bytes
                .extend_from_slice(&slice[..take]);
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
        (
            cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            5,
            16,
        ),
    ] {
        let mut server = established(suite, 4);
        let payload = b"head-body-control";
        assert_eq!(server.writer().write(payload).unwrap(), payload.len());
        let initial = server.write_progress().unwrap();
        assert_eq!(initial.accepted_plaintext, payload.len() as u64);
        assert_eq!(initial.written_plaintext, 0);
        assert_eq!(initial.complete_records_plaintext, 0);
        let total = prefix + payload.len() + suffix;
        let mut raw = Prefix {
            limit: 1,
            bytes: Vec::new(),
        };
        for end in 1..=total {
            assert_eq!(server.write_tls(&mut raw).unwrap(), 1);
            let progress = server.write_progress().unwrap();
            assert_eq!(
                progress.written_plaintext,
                end.saturating_sub(prefix)
                    .min(payload.len()) as u64
            );
            assert_eq!(
                progress.complete_records_plaintext,
                if end == total {
                    payload.len() as u64
                } else {
                    0
                }
            );
            assert_eq!(progress.fault, None);
        }
        assert_eq!(raw.bytes.len(), total);
        assert!(!server.wants_write());
        server.send_close_notify();
        server
            .write_tls(&mut io::sink())
            .unwrap();
        assert_eq!(
            server
                .write_progress()
                .unwrap()
                .written_plaintext,
            payload.len() as u64
        );
    }
}

#[test]
fn nonempty_zero_preserves_prior_progress_and_poison_is_sticky() {
    let mut server = established(cipher_suite::TLS13_AES_128_GCM_SHA256, 1);
    server
        .writer()
        .write_all(b"payload")
        .unwrap();
    let mut raw = Prefix {
        limit: 6,
        bytes: Vec::new(),
    };
    assert_eq!(server.write_tls(&mut raw).unwrap(), 6);
    assert_eq!(
        server
            .write_progress()
            .unwrap()
            .written_plaintext,
        1
    );
    raw.limit = 0;
    assert_eq!(
        server
            .write_tls(&mut raw)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WriteZero
    );
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
    assert_eq!(
        server
            .writer()
            .write(b"second")
            .unwrap(),
        0
    );
    let mut raw = Prefix {
        limit: 10,
        bytes: Vec::new(),
    };
    server.write_tls(&mut raw).unwrap();
    assert_eq!(
        server
            .write_progress()
            .unwrap()
            .written_plaintext,
        5
    );
    assert_eq!(
        server
            .writer()
            .write(b"second")
            .unwrap(),
        0
    );
    raw.limit = usize::MAX;
    server.write_tls(&mut raw).unwrap();
    assert_eq!(
        server
            .write_progress()
            .unwrap()
            .complete_records_plaintext,
        5
    );
    assert_eq!(
        server
            .writer()
            .write(b"second")
            .unwrap(),
        6
    );
    assert_eq!(
        server
            .write_progress()
            .unwrap()
            .accepted_plaintext,
        11
    );
}

#[test]
fn enum_drain_cannot_bypass_tracking_and_empty_zero_is_not_failure() {
    let mut server = established(cipher_suite::TLS13_AES_128_GCM_SHA256, 1);
    let mut zero = Prefix {
        limit: 0,
        bytes: Vec::new(),
    };
    assert_eq!(server.write_tls(&mut zero).unwrap(), 0);
    assert_eq!(server.write_progress().unwrap().fault, None);
    server.writer().write_all(b"x").unwrap();
    let mut server = rustls::Connection::Server(server);
    assert_eq!(
        server
            .write_tls(&mut zero)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!(
        server.write_progress().unwrap().fault,
        Some(WriteTrackingFault::WriteZero)
    );
}

#[test]
fn late_enable_is_refused_even_after_application_record_is_drained() {
    let provider = aws_lc_rs::default_provider();
    let (mut client, mut server) = rustls_test::make_pair(KeyType::Rsa2048, &provider);
    do_handshake(&mut client, &mut server);
    server
        .writer()
        .write_all(b"untracked")
        .unwrap();
    while server.wants_write() {
        server
            .write_tls(&mut io::sink())
            .unwrap();
    }
    assert!(
        server
            .enable_write_tracking(WriteTrackingLimits {
                max_pending_records: 4
            })
            .is_err()
    );
}

#[derive(Default)]
struct FailureSwitch {
    armed: AtomicBool,
    remaining: AtomicUsize,
    sequences: Mutex<Vec<u64>>,
    mapping: AtomicUsize,
}

struct FailingAead {
    inner: &'static dyn Tls13AeadAlgorithm,
    switch: Arc<FailureSwitch>,
}

impl Tls13AeadAlgorithm for FailingAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(FailingEncrypter {
            inner: self.inner.encrypter(key, iv),
            switch: self.switch.clone(),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.inner.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.inner.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<rustls::ConnectionTrafficSecrets, UnsupportedOperationError> {
        self.inner.extract_keys(key, iv)
    }
}

struct FailingEncrypter {
    inner: Box<dyn MessageEncrypter>,
    switch: Arc<FailureSwitch>,
}

impl MessageEncrypter for FailingEncrypter {
    fn plaintext_ciphertext_range(&self, len: usize) -> Option<std::ops::Range<usize>> {
        match self
            .switch
            .mapping
            .load(Ordering::SeqCst)
        {
            1 => None,
            2 => Some(0..len + 1),
            _ => self
                .inner
                .plaintext_ciphertext_range(len),
        }
    }

    fn encrypted_payload_len(&self, len: usize) -> usize {
        self.inner.encrypted_payload_len(len)
    }

    fn encrypt(
        &mut self,
        message: OutboundPlainMessage<'_>,
        sequence: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        if self.switch.armed.load(Ordering::SeqCst) {
            self.switch
                .sequences
                .lock()
                .unwrap()
                .push(sequence);
            if self
                .switch
                .remaining
                .load(Ordering::SeqCst)
                == 0
            {
                return Err(rustls::Error::EncryptError);
            }
            self.switch
                .remaining
                .fetch_sub(1, Ordering::SeqCst);
        }
        self.inner.encrypt(message, sequence)
    }
}

fn failing_connection() -> (ServerConnection, Arc<FailureSwitch>) {
    let (_, server, switch) = failing_pair();
    (server, switch)
}

fn failing_pair() -> (
    rustls::ClientConnection,
    ServerConnection,
    Arc<FailureSwitch>,
) {
    let SupportedCipherSuite::Tls13(base) = cipher_suite::TLS13_AES_128_GCM_SHA256 else {
        unreachable!()
    };
    let switch = Arc::new(FailureSwitch::default());
    let algorithm = Box::leak(Box::new(FailingAead {
        inner: base.aead_alg,
        switch: switch.clone(),
    }));
    let suite = Box::leak(Box::new(rustls::Tls13CipherSuite {
        common: rustls::CipherSuiteCommon {
            suite: base.common.suite,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        hkdf_provider: base.hkdf_provider,
        aead_alg: algorithm,
        quic: None,
    }));
    let (client, server) = established_pair(SupportedCipherSuite::Tls13(suite), 4);
    (client, server, switch)
}

#[test]
fn actual_provider_failure_keeps_only_the_encrypted_prefix_and_never_reuses_sequence() {
    for successful_fragments in [0, 1] {
        let (mut server, switch) = failing_connection();
        server
            .writer()
            .write_all(b"previous")
            .unwrap();
        server
            .write_tls(&mut io::sink())
            .unwrap();
        let prior = server.write_progress().unwrap();
        switch
            .remaining
            .store(successful_fragments, Ordering::SeqCst);
        switch
            .armed
            .store(true, Ordering::SeqCst);
        let result = server.writer().write(&vec![42; 16385]);
        if successful_fragments == 0 {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), 16384);
        }
        let after = server.write_progress().unwrap();
        assert_eq!(
            after.accepted_plaintext,
            prior.accepted_plaintext + successful_fragments as u64 * 16384
        );
        assert_eq!(after.written_plaintext, prior.written_plaintext);
        assert_eq!(
            after.complete_records_plaintext,
            prior.complete_records_plaintext
        );
        assert_eq!(after.fault, Some(WriteTrackingFault::Encryption));
        let attempted = switch.sequences.lock().unwrap().clone();
        assert_eq!(attempted.len(), successful_fragments + 1);
        assert!(
            attempted
                .windows(2)
                .all(|pair| pair[1] == pair[0] + 1)
        );
        assert!(server.writer().write(b"retry").is_err());
        assert!(server.writer().flush().is_err());
        assert!(
            server
                .write_tls(&mut io::sink())
                .is_err()
        );
        assert!(server.refresh_traffic_keys().is_err());
        assert_eq!(*switch.sequences.lock().unwrap(), attempted);
    }
}

#[test]
fn control_encryption_failure_is_latched_without_panicking_or_retrying_alerts() {
    for key_update in [false, true] {
        let (mut server, switch) = failing_connection();
        switch
            .armed
            .store(true, Ordering::SeqCst);
        if key_update {
            assert!(server.refresh_traffic_keys().is_err());
        } else {
            server.send_close_notify();
        }
        let progress = server.write_progress().unwrap();
        assert_eq!(progress.accepted_plaintext, 0);
        assert_eq!(progress.written_plaintext, 0);
        assert_eq!(progress.fault, Some(WriteTrackingFault::Encryption));
        server.send_close_notify();
        assert!(
            server
                .write_tls(&mut io::sink())
                .is_err()
        );
        assert_eq!(switch.sequences.lock().unwrap().len(), 1);
    }
}

#[test]
fn unavailable_or_invalid_provider_mapping_refuses_before_output() {
    for (mapping, fault) in [
        (1, WriteTrackingFault::Unsupported),
        (2, WriteTrackingFault::Integrity),
    ] {
        let (mut server, switch) = failing_connection();
        switch
            .mapping
            .store(mapping, Ordering::SeqCst);
        switch
            .armed
            .store(true, Ordering::SeqCst);
        assert!(server.writer().write(b"body").is_err());
        assert_eq!(
            server
                .write_progress()
                .unwrap()
                .accepted_plaintext,
            0
        );
        assert_eq!(server.write_progress().unwrap().fault, Some(fault));
        assert!(
            server
                .write_tls(&mut io::sink())
                .is_err()
        );
        assert!(
            switch
                .sequences
                .lock()
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn received_key_update_encryption_failure_reaches_packet_boundary() {
    let (mut client, mut server, switch) = failing_pair();
    client.refresh_traffic_keys().unwrap();
    switch
        .armed
        .store(true, Ordering::SeqCst);
    rustls_test::transfer(&mut client, &mut server);
    assert!(server.process_new_packets().is_err());
    let progress = server.write_progress().unwrap();
    assert_eq!(progress.accepted_plaintext, 0);
    assert_eq!(progress.written_plaintext, 0);
    assert_eq!(progress.fault, Some(WriteTrackingFault::Encryption));
    assert!(
        server
            .write_tls(&mut io::sink())
            .is_err()
    );
    assert_eq!(switch.sequences.lock().unwrap().len(), 1);
}

#[test]
fn key_update_and_multiple_application_records_keep_logical_order() {
    let mut server = established(cipher_suite::TLS13_AES_128_GCM_SHA256, 4);
    server.refresh_traffic_keys().unwrap();
    let mut control = Prefix {
        limit: usize::MAX,
        bytes: Vec::new(),
    };
    server.write_tls(&mut control).unwrap();
    assert!(!control.bytes.is_empty());
    assert_eq!(
        server
            .write_progress()
            .unwrap()
            .written_plaintext,
        0
    );
    server
        .writer()
        .write_all(b"head")
        .unwrap();
    server
        .writer()
        .write_all(b"body")
        .unwrap();
    let mut raw = Prefix {
        limit: 26 + 6,
        bytes: Vec::new(),
    };
    assert_eq!(server.write_tls(&mut raw).unwrap(), 32);
    let progress = server.write_progress().unwrap();
    assert_eq!(progress.accepted_plaintext, 8);
    assert_eq!(progress.written_plaintext, 5);
    assert_eq!(progress.complete_records_plaintext, 4);
    raw.limit = usize::MAX;
    server.write_tls(&mut raw).unwrap();
    assert_eq!(
        server
            .write_progress()
            .unwrap()
            .complete_records_plaintext,
        8
    );
}

#[test]
fn pending_is_distinct_from_oversized_writer_return_and_error_keeps_progress() {
    struct Refusal(io::ErrorKind);
    impl Write for Refusal {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(self.0.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct Oversized;
    impl Write for Oversized {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len() + 1)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for malformed in [false, true] {
        let mut server = established(cipher_suite::TLS13_AES_128_GCM_SHA256, 2);
        server
            .writer()
            .write_all(b"body")
            .unwrap();
        assert_eq!(
            server
                .write_tls(&mut Refusal(io::ErrorKind::WouldBlock))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            server
                .write_progress()
                .unwrap()
                .written_plaintext,
            0
        );
        assert_eq!(server.write_progress().unwrap().fault, None);
        server
            .write_tls(&mut Prefix {
                limit: 6,
                bytes: Vec::new(),
            })
            .unwrap();
        if malformed {
            assert!(
                server
                    .write_tls(&mut Oversized)
                    .is_err()
            );
        } else {
            assert!(
                server
                    .write_tls(&mut Refusal(io::ErrorKind::BrokenPipe))
                    .is_err()
            );
        }
        let progress = server.write_progress().unwrap();
        assert_eq!(progress.written_plaintext, 1);
        assert_eq!(progress.complete_records_plaintext, 0);
        assert_eq!(
            progress.fault,
            Some(if malformed {
                WriteTrackingFault::Integrity
            } else {
                WriteTrackingFault::Io
            })
        );
    }
}
