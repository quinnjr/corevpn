//! Protocol Performance Benchmarks
//!
//! Benchmarks for packet parsing, serialization, and reliable transport.

use bytes::{Bytes, BytesMut};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use corevpn_protocol::{
    KeyId, OpCode, Packet, PacketHeader, ReliableConfig, ReliableTransport, TlsRecordReassembler,
};

// =============================================================================
// Packet Parsing Benchmarks
// =============================================================================

fn bench_packet_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_parse");

    // Hard reset packet (control channel init)
    let hard_reset = [
        0x38, // opcode=7 (HARD_RESET_CLIENT_V2), key_id=0
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // session_id
        0x00, // ack_count = 0
    ];

    group.bench_function("hard_reset", |b| {
        b.iter(|| Packet::parse(black_box(&hard_reset), false));
    });

    // Control packet with ACKs and payload
    let control_with_acks = {
        let mut data = vec![
            0x20, // opcode=4 (CONTROL_V1), key_id=0
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // session_id
            0x02, // ack_count = 2
            0x00, 0x00, 0x00, 0x01, // ack 1
            0x00, 0x00, 0x00, 0x02, // ack 2
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // remote session_id
            0x00, 0x00, 0x00, 0x03, // message packet_id
        ];
        // Add 256 bytes of TLS payload
        data.extend(vec![0xAB; 256]);
        data
    };

    group.bench_function("control_with_acks", |b| {
        b.iter(|| Packet::parse(black_box(&control_with_acks), false));
    });

    // Data packet V2
    let data_v2 = {
        let mut data = vec![
            0x48, // opcode=9 (DataV2), key_id=0
            0x00, 0x00, 0x01, // peer_id = 1
        ];
        // Add 1400 bytes of encrypted payload (typical MTU)
        data.extend(vec![0xDE; 1400]);
        data
    };

    group.throughput(Throughput::Bytes(1400));
    group.bench_function("data_v2_1400", |b| {
        b.iter(|| Packet::parse(black_box(&data_v2), false));
    });

    // Control packet with tls-auth (HMAC)
    let control_with_hmac = {
        let mut data = vec![0x20]; // opcode
        data.extend([0u8; 32]); // HMAC
        data.extend([0u8; 4]); // packet_id
        data.extend([0u8; 4]); // timestamp
        data.extend([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // session_id
        data.push(0x00); // ack_count
        data.extend([0u8; 4]); // message packet_id
        data.extend(vec![0xAB; 128]); // payload
        data
    };

    group.bench_function("control_with_hmac", |b| {
        b.iter(|| Packet::parse(black_box(&control_with_hmac), true));
    });

    group.finish();
}

fn bench_packet_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_serialize");

    // Parse then serialize to measure serialize performance
    let control_packet_data = {
        let mut data = vec![
            0x20, // opcode=4 (CONTROL_V1), key_id=0
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // session_id
            0x00, // ack_count = 0
            0x00, 0x00, 0x00, 0x01, // message packet_id
        ];
        data.extend(vec![0xAB; 256]);
        data
    };

    let packet = Packet::parse(&control_packet_data, false).unwrap();

    group.bench_function("control_256b", |b| {
        b.iter(|| black_box(&packet).serialize());
    });

    // Data packet
    let data_packet_raw = {
        let mut data = vec![
            0x48, // opcode=9 (DataV2), key_id=0
            0x00, 0x00, 0x01, // peer_id = 1
        ];
        data.extend(vec![0xDE; 1400]);
        data
    };

    let data_packet = Packet::parse(&data_packet_raw, false).unwrap();

    group.throughput(Throughput::Bytes(1400));
    group.bench_function("data_1400b", |b| {
        b.iter(|| black_box(&data_packet).serialize());
    });

    group.finish();
}

// =============================================================================
// Header Parsing Benchmarks
// =============================================================================

fn bench_header_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_parse");

    // Data channel header (minimal)
    let data_header = [0x48]; // DataV2

    group.bench_function("data_minimal", |b| {
        b.iter(|| PacketHeader::parse(black_box(&data_header), false));
    });

    // Control channel header without HMAC
    let control_header = [
        0x20, // CONTROL_V1
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // session_id
    ];

    group.bench_function("control_no_hmac", |b| {
        b.iter(|| PacketHeader::parse(black_box(&control_header), false));
    });

    // Control channel header with HMAC (tls-auth)
    let control_hmac_header = {
        let mut data = vec![0x20]; // CONTROL_V1
        data.extend([0u8; 32]); // HMAC
        data.extend([0u8; 4]); // packet_id  
        data.extend([0u8; 4]); // timestamp
        data.extend([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // session_id
        data
    };

    group.bench_function("control_with_hmac", |b| {
        b.iter(|| PacketHeader::parse(black_box(&control_hmac_header), true));
    });

    group.finish();
}

// =============================================================================
// Reliable Transport Benchmarks
// =============================================================================

fn bench_reliable_transport(c: &mut Criterion) {
    let mut group = c.benchmark_group("reliable_transport");

    let config = ReliableConfig::default();

    group.bench_function("create", |b| {
        b.iter(|| ReliableTransport::new(config.clone()));
    });

    // Send messages
    let payload = Bytes::from(vec![0xABu8; 256]);

    group.bench_function("send", |b| {
        let mut transport = ReliableTransport::new(config.clone());
        b.iter(|| {
            let result = transport.send(black_box(payload.clone()));
            // Clear pending to avoid window full
            transport.process_acks(&[transport.has_pending() as u32]);
            result
        });
    });

    // Process received ACKs
    group.bench_function("process_acks", |b| {
        let mut transport = ReliableTransport::new(config.clone());
        // Queue some packets first
        for _ in 0..5 {
            let _ = transport.send(payload.clone());
        }

        b.iter(|| {
            transport.process_acks(black_box(&[1, 2, 3, 4, 5]));
        });
    });

    // Receive and deliver
    group.bench_function("receive", |b| {
        let payload = Bytes::from(vec![0xABu8; 256]);
        b.iter(|| {
            let mut transport = ReliableTransport::new(config.clone());
            transport.receive(black_box(0), black_box(payload.clone()))
        });
    });

    group.finish();
}

// =============================================================================
// TLS Record Reassembly Benchmarks
// =============================================================================

fn bench_tls_reassembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("tls_reassembly");

    group.bench_function("create", |b| {
        b.iter(|| TlsRecordReassembler::new(16384));
    });

    // Simulate adding TLS record data (use small data that won't overflow)
    let data = vec![0xABu8; 64];

    group.bench_function("add", |b| {
        b.iter(|| {
            let mut reassembler = TlsRecordReassembler::new(16384);
            reassembler.add(black_box(&data)).unwrap();
        });
    });

    // Extract complete TLS records
    group.bench_function("extract_records", |b| {
        // Create a complete TLS record (5 byte header + payload)
        let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x10]; // type, version, length=16
        record.extend(vec![0xAB; 16]);

        b.iter(|| {
            let mut reassembler = TlsRecordReassembler::new(16384);
            reassembler.add(&record).unwrap();
            reassembler.extract_records()
        });
    });

    group.finish();
}

// =============================================================================
// OpCode Benchmarks
// =============================================================================

fn bench_opcode(c: &mut Criterion) {
    let mut group = c.benchmark_group("opcode");

    group.bench_function("from_byte", |b| {
        b.iter(|| OpCode::from_byte(black_box(0x38)));
    });

    group.bench_function("to_byte", |b| {
        let opcode = OpCode::HardResetClientV2;
        let key_id = KeyId::new(0);
        b.iter(|| opcode.to_byte(black_box(key_id)));
    });

    group.bench_function("is_data", |b| {
        let opcode = OpCode::DataV2;
        b.iter(|| black_box(opcode).is_data());
    });

    group.finish();
}

// =============================================================================
// Bytes Operations Benchmarks
// =============================================================================

fn bench_bytes_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes_ops");

    // Measure Bytes::copy_from_slice overhead
    let data = vec![0xABu8; 1400];

    group.throughput(Throughput::Bytes(1400));
    group.bench_function("copy_from_slice_1400", |b| {
        b.iter(|| Bytes::copy_from_slice(black_box(&data)));
    });

    // BytesMut allocation and writing
    group.bench_function("bytesmut_alloc_write_1400", |b| {
        let payload = vec![0xABu8; 1400];
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(1500);
            buf.extend_from_slice(&payload);
            buf.freeze()
        });
    });

    // Pre-allocated BytesMut
    group.bench_function("bytesmut_prealloc_write_1400", |b| {
        let payload = vec![0xABu8; 1400];
        let mut buf = BytesMut::with_capacity(1500);
        b.iter(|| {
            buf.clear();
            buf.extend_from_slice(black_box(&payload));
            buf.len()
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_packet_parse,
    bench_packet_serialize,
    bench_header_parse,
    bench_reliable_transport,
    bench_tls_reassembly,
    bench_opcode,
    bench_bytes_ops,
);

criterion_main!(benches);
