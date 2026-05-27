use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::io::Cursor;

use wrongsv_net_types::Address;
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless::MemoryValidator;
use wrongsv_vless::Validator;
use wrongsv_vless::vision::{TrafficState, VisionReader, VisionWriter};
use wrongsv_vless_encoding::{self as encoding, Addons};

fn bench_encode_request(c: &mut Criterion) {
    let uuid = Uuid::new_v4();
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uuid),
            flow: String::new(),
            encryption: String::new(),
            udp: true,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "bench@example.com".into(),
        level: 0,
    };

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("192.168.1.1"),
        port: wrongsv_net_types::Port(443),
        user,
    };

    let addons = Addons {
        flow: String::new(),
        ..Default::default()
    };

    c.bench_function("encode_request_header", |b| {
        b.iter(|| {
            let mut buf = bytes::BytesMut::with_capacity(512);
            encoding::encode_request_header(&mut buf, &request, &addons).unwrap();
            black_box(buf);
        });
    });
}

fn bench_decode_request(c: &mut Criterion) {
    let uuid = Uuid::new_v4();
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uuid),
            flow: String::new(),
            encryption: String::new(),
            udp: true,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "bench@example.com".into(),
        level: 0,
    };

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("192.168.1.1"),
        port: wrongsv_net_types::Port(443),
        user,
    };

    let addons = Addons {
        flow: String::new(),
        ..Default::default()
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();
    let raw = buf.freeze();

    let validator = MemoryValidator::new();
    validator.add(request.user.clone()).unwrap();

    c.bench_function("decode_request_header", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(raw.as_ref());
            let v = &validator;
            let decoded = encoding::decode_request_header(&mut cursor, |id| v.get(id)).unwrap();
            black_box(decoded);
        });
    });
}

fn bench_xtls_padding(c: &mut Criterion) {
    let uuid = Uuid::new_v4();
    let user_sent_id = uuid.as_bytes();
    let data = vec![0u8; 1460]; // typical MTU payload

    c.bench_function("xtls_padding_1460", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(2048);
            let state = TrafficState::new(user_sent_id);
            let mut writer = VisionWriter::new(&mut buf, state, false, vec![900, 500, 900, 256]);
            writer.write(&data).unwrap();
            writer.flush().unwrap();
            black_box(buf);
        });
    });
}

fn bench_xtls_unpadding(c: &mut Criterion) {
    let uuid = Uuid::new_v4();
    let user_sent_id = uuid.as_bytes();
    let data = vec![b'X'; 1460];

    // Pre-create padded data
    let mut padded = Vec::new();
    {
        let state = TrafficState::new(user_sent_id);
        let mut writer = VisionWriter::new(&mut padded, state, false, vec![900, 500, 900, 256]);
        writer.write(&data).unwrap();
        writer.flush().unwrap();
    }

    c.bench_function("xtls_unpadding_1460", |b| {
        b.iter(|| {
            let state = TrafficState::new(user_sent_id);
            let mut reader = VisionReader::new(&padded[..], state, true);
            let mut out = vec![0u8; 2048];
            let n = reader.read(&mut out).unwrap();
            black_box((n, out));
        });
    });
}

fn bench_xtls_padding_sizes(c: &mut Criterion) {
    let uuid = Uuid::new_v4();
    let user_sent_id = uuid.as_bytes();
    let sizes: &[(usize, &str)] = &[
        (64, "64B"),
        (256, "256B"),
        (1024, "1K"),
        (8192, "8K"),
        (16384, "16K"),
        (65536, "64K"),
    ];

    for &(size, label) in sizes {
        let data = vec![0u8; size];
        c.bench_function(&format!("xtls_padding_{label}"), |b| {
            b.iter(|| {
                let state = TrafficState::new(user_sent_id);
                let mut buf = Vec::with_capacity(size + 512);
                let mut writer =
                    VisionWriter::new(&mut buf, state, false, vec![900, 500, 900, 256]);
                writer.write(&data).unwrap();
                writer.flush().unwrap();
                black_box(buf);
            });
        });
    }
}

fn bench_xtls_unpadding_sizes(c: &mut Criterion) {
    let uuid = Uuid::new_v4();
    let user_sent_id = uuid.as_bytes();
    let sizes: &[(usize, &str)] = &[
        (64, "64B"),
        (256, "256B"),
        (1024, "1K"),
        (8192, "8K"),
        (16384, "16K"),
        (65536, "64K"),
    ];

    for &(size, label) in sizes {
        let data = vec![b'X'; size];
        let mut padded = Vec::new();
        {
            let state = TrafficState::new(user_sent_id);
            let mut writer = VisionWriter::new(&mut padded, state, false, vec![900, 500, 900, 256]);
            writer.write(&data).unwrap();
            writer.flush().unwrap();
        }

        c.bench_function(&format!("xtls_unpadding_{label}"), |b| {
            b.iter(|| {
                let state = TrafficState::new(user_sent_id);
                let mut reader = VisionReader::new(&padded[..], state, true);
                let mut out = vec![0u8; size + 1024];
                let n = reader.read(&mut out).unwrap();
                black_box((n, out));
            });
        });
    }
}

fn bench_vision_roundtrip(c: &mut Criterion) {
    let uuid = Uuid::new_v4();
    let user_sent_id = uuid.as_bytes();
    let sizes: &[(usize, &str)] = &[(64, "64B"), (1024, "1K"), (8192, "8K"), (65536, "64K")];

    for &(size, label) in sizes {
        let data = vec![b'X'; size];
        c.bench_function(&format!("vision_roundtrip_{label}"), |b| {
            b.iter(|| {
                // Pad
                let state = TrafficState::new(user_sent_id);
                let mut padded = Vec::with_capacity(size + 1024);
                {
                    let mut writer =
                        VisionWriter::new(&mut padded, state, false, vec![900, 500, 900, 256]);
                    writer.write(&data).unwrap();
                    writer.flush().unwrap();
                }
                // Unpad
                let state = TrafficState::new(user_sent_id);
                let mut reader = VisionReader::new(&padded[..], state, true);
                let mut out = vec![0u8; size + 1024];
                let n = reader.read(&mut out).unwrap();
                black_box((n, out));
            });
        });
    }
}

fn bench_memcpy_throughput(c: &mut Criterion) {
    // Theoretical upper bound: raw memcpy throughput for comparison
    let sizes: &[(usize, &str)] = &[(1024, "1K"), (8192, "8K"), (16384, "16K"), (65536, "64K")];

    for &(size, label) in sizes {
        let src = vec![0xAAu8; size];
        let mut dst = vec![0u8; size];
        c.bench_function(&format!("memcpy_{label}"), |b| {
            b.iter(|| {
                dst.copy_from_slice(&src);
                black_box(&dst);
            });
        });
    }
}

criterion_group!(
    benches,
    bench_encode_request,
    bench_decode_request,
    bench_xtls_padding,
    bench_xtls_unpadding,
    bench_xtls_padding_sizes,
    bench_xtls_unpadding_sizes,
    bench_vision_roundtrip,
    bench_memcpy_throughput,
);
criterion_main!(benches);
