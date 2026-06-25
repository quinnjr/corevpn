//! Cryptographic Performance Benchmarks
//!
//! Benchmarks for CoreVPN's cryptographic operations to identify bottlenecks
//! and measure performance improvements.

use corevpn_crypto::{
    Cipher, CipherSuite, DataChannelKey, HmacAuth, KeyPair, PacketCipher, SigningKey, StaticSecret,
    derive_keys, random_bytes,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

// =============================================================================
// Cipher Benchmarks
// =============================================================================

fn bench_cipher_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipher_encrypt");

    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let aad = b"associated data";

    // Test various payload sizes (common VPN packet sizes)
    for size in [64, 256, 512, 1024, 1400, 4096, 16384].iter() {
        let plaintext = vec![0xABu8; *size];

        for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
            let cipher = Cipher::new(&key, suite);
            let name = match suite {
                CipherSuite::ChaCha20Poly1305 => "chacha20",
                CipherSuite::Aes256Gcm => "aes256gcm",
            };

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(BenchmarkId::new(name, size), size, |b, _| {
                b.iter(|| cipher.encrypt(black_box(&nonce), black_box(&plaintext), black_box(aad)));
            });
        }
    }

    group.finish();
}

fn bench_cipher_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("cipher_decrypt");

    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let aad = b"associated data";

    for size in [64, 256, 512, 1024, 1400, 4096, 16384].iter() {
        let plaintext = vec![0xABu8; *size];

        for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
            let cipher = Cipher::new(&key, suite);
            let ciphertext = cipher.encrypt(&nonce, &plaintext, aad).unwrap();

            let name = match suite {
                CipherSuite::ChaCha20Poly1305 => "chacha20",
                CipherSuite::Aes256Gcm => "aes256gcm",
            };

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(BenchmarkId::new(name, size), size, |b, _| {
                b.iter(|| {
                    cipher.decrypt(black_box(&nonce), black_box(&ciphertext), black_box(aad))
                });
            });
        }
    }

    group.finish();
}

fn bench_packet_cipher(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_cipher");

    // Simulate real VPN packet processing with nonce management + replay protection
    for size in [64, 512, 1400].iter() {
        let plaintext = vec![0xABu8; *size];

        for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
            let name = match suite {
                CipherSuite::ChaCha20Poly1305 => "chacha20",
                CipherSuite::Aes256Gcm => "aes256gcm",
            };

            group.throughput(Throughput::Bytes(*size as u64));

            // Encrypt benchmark
            group.bench_with_input(
                BenchmarkId::new(format!("{}_encrypt", name), size),
                size,
                |b, _| {
                    let key = DataChannelKey::new([0x42u8; 32], suite);
                    let mut cipher = PacketCipher::new(key);
                    let ad = &[0x48u8, 0x00, 0x00, 0x01];
                    b.iter(|| cipher.encrypt(black_box(&plaintext), black_box(ad)));
                },
            );

            // Decrypt benchmark
            group.bench_with_input(
                BenchmarkId::new(format!("{}_decrypt", name), size),
                size,
                |b, _| {
                    let key = DataChannelKey::new([0x42u8; 32], suite);
                    let mut encryptor = PacketCipher::new(key);

                    let ad = &[0x48u8, 0x00, 0x00, 0x01];
                    // Pre-encrypt packets
                    let packets: Vec<_> = (0..1000)
                        .map(|_| encryptor.encrypt(&plaintext, ad).unwrap())
                        .collect();

                    let key2 = DataChannelKey::new([0x42u8; 32], suite);
                    let mut decryptor = PacketCipher::new(key2);
                    let mut idx = 0;

                    b.iter(|| {
                        let result = decryptor.decrypt(black_box(&packets[idx]), black_box(ad));
                        idx = (idx + 1) % packets.len();
                        result
                    });
                },
            );
        }
    }

    group.finish();
}

// =============================================================================
// Key Exchange Benchmarks
// =============================================================================

fn bench_key_exchange(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_exchange");

    group.bench_function("x25519_keygen", |b| {
        b.iter(StaticSecret::generate);
    });

    group.bench_function("x25519_dh", |b| {
        let alice = StaticSecret::generate();
        let bob = StaticSecret::generate();
        let bob_public = bob.public_key();

        b.iter(|| alice.diffie_hellman(black_box(&bob_public)));
    });

    group.bench_function("keypair_generate", |b| {
        b.iter(KeyPair::generate);
    });

    group.finish();
}

// =============================================================================
// Signing Benchmarks
// =============================================================================

fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");

    let key = SigningKey::generate();
    let verifying = key.verifying_key();

    for size in [32, 256, 1024, 4096].iter() {
        let message = vec![0xABu8; *size];
        let signature = key.sign(&message);

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("ed25519_sign", size), size, |b, _| {
            b.iter(|| key.sign(black_box(&message)));
        });

        group.bench_with_input(BenchmarkId::new("ed25519_verify", size), size, |b, _| {
            b.iter(|| verifying.verify(black_box(&message), black_box(&signature)));
        });
    }

    group.finish();
}

// =============================================================================
// KDF Benchmarks
// =============================================================================

fn bench_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf");

    let shared_secret = [0x42u8; 32];
    let client_random = [0x01u8; 32];
    let server_random = [0x02u8; 32];
    let info = b"OpenVPN data channel";

    group.bench_function("hkdf_derive_keys", |b| {
        b.iter(|| {
            derive_keys(
                black_box(&shared_secret),
                black_box(&client_random),
                black_box(&server_random),
                black_box(info),
            )
        });
    });

    group.finish();
}

// =============================================================================
// HMAC Auth Benchmarks
// =============================================================================

fn bench_hmac_auth(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_auth");

    let key = [0x42u8; 32];
    let auth = HmacAuth::from_single_key(key);

    for size in [64, 256, 512, 1024, 1400].iter() {
        let data = vec![0xABu8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("authenticate", size), size, |b, _| {
            b.iter(|| auth.authenticate(black_box(&data)));
        });

        let tag = auth.authenticate(&data);
        group.bench_with_input(BenchmarkId::new("verify", size), size, |b, _| {
            b.iter(|| auth.verify(black_box(&data), black_box(&tag)));
        });

        // Wrap/unwrap (full operation)
        group.bench_with_input(BenchmarkId::new("wrap", size), size, |b, _| {
            b.iter(|| auth.wrap(black_box(&data)));
        });
    }

    group.finish();
}

// =============================================================================
// RNG Benchmarks
// =============================================================================

fn bench_rng(c: &mut Criterion) {
    let mut group = c.benchmark_group("rng");

    group.bench_function("random_8_bytes", |b| {
        b.iter(random_bytes::<8>);
    });

    group.bench_function("random_32_bytes", |b| {
        b.iter(random_bytes::<32>);
    });

    group.bench_function("random_64_bytes", |b| {
        b.iter(random_bytes::<64>);
    });

    group.finish();
}

// =============================================================================
// Combined VPN Packet Processing Simulation
// =============================================================================

fn bench_full_packet_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");

    // Simulate full encrypt path: HMAC + encrypt (typical OpenVPN with tls-auth)
    let hmac_key = [0x42u8; 32];
    let hmac = HmacAuth::from_single_key(hmac_key);

    for size in [512, 1400].iter() {
        let plaintext = vec![0xABu8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        // Full encrypt path
        group.bench_with_input(BenchmarkId::new("encrypt_with_hmac", size), size, |b, _| {
            let key = DataChannelKey::new([0x42u8; 32], CipherSuite::ChaCha20Poly1305);
            let mut cipher = PacketCipher::new(key);

            b.iter(|| {
                let encrypted = cipher.encrypt(black_box(&plaintext), &[]).unwrap();
                let tag = hmac.authenticate(&encrypted);
                (encrypted, tag)
            });
        });

        // Full decrypt path
        group.bench_with_input(BenchmarkId::new("decrypt_with_hmac", size), size, |b, _| {
            let key = DataChannelKey::new([0x42u8; 32], CipherSuite::ChaCha20Poly1305);
            let mut encryptor = PacketCipher::new(key);

            let packets: Vec<_> = (0..1000)
                .map(|_| {
                    let encrypted = encryptor.encrypt(&plaintext, &[]).unwrap();
                    let tag = hmac.authenticate(&encrypted);
                    (encrypted, tag)
                })
                .collect();

            let key2 = DataChannelKey::new([0x42u8; 32], CipherSuite::ChaCha20Poly1305);
            let mut decryptor = PacketCipher::new(key2);
            let mut idx = 0;

            b.iter(|| {
                let (encrypted, tag) = &packets[idx];
                idx = (idx + 1) % packets.len();

                // Verify HMAC first
                hmac.verify(black_box(encrypted), black_box(tag)).unwrap();
                // Then decrypt
                decryptor.decrypt(black_box(encrypted), &[])
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_cipher_encrypt,
    bench_cipher_decrypt,
    bench_packet_cipher,
    bench_key_exchange,
    bench_signing,
    bench_kdf,
    bench_hmac_auth,
    bench_rng,
    bench_full_packet_pipeline,
);

criterion_main!(benches);
