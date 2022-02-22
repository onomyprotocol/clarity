#[macro_use]
extern crate criterion;
extern crate clarity;

use clarity::{PrivateKey, Transaction};
use criterion::Criterion;

fn tx_sign_bench(c: &mut Criterion) {
    let key: PrivateKey = "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0"
        .parse()
        .unwrap();
    let tx = Transaction {
        nonce: u256!(0),
        gas_price: u256!(1000000000000),
        gas_limit: u256!(10000),
        to: "13978aee95f38490e9769c39b2773ed763d9cd5f".parse().unwrap(),
        value: u256!(10000000000000000),
        data: Vec::new(),
        signature: None,
    };

    let signed_tx = tx.sign(&key, None);

    c.bench_function("sign tx without network id", move |b| {
        b.iter(|| tx.sign(&key, None))
    });

    c.bench_function("recover sender", move |b| {
        b.iter(|| {
            signed_tx.sender().unwrap();
        })
    });
}

fn private_key_to_public(c: &mut Criterion) {
    let key: PrivateKey = "0102010201020102010201020102010201020102010201020102010201020102"
        .parse()
        .unwrap();

    c.bench_function("private key to public", move |b| {
        b.iter(|| key.to_address())
    });
}

criterion_group!(benches, tx_sign_bench, private_key_to_public);
criterion_main!(benches);
