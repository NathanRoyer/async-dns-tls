# async-dns-tls

DNS-over-TLS allows secure retrieval of domain name information.

This crate's encoding and decoding of DNS messages is based on RFC1035.

## Example

```rust
let roots = webpki_roots::TLS_SERVER_ROOTS.iter().cloned();
let root_store = rustls::RootCertStore::from_iter(roots);

let tls_config = rustls::ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_no_client_auth();

let tls_config = std::sync::Arc::new(tls_config);

let task = async {
    let cloudflare_dns = [1, 1, 1, 1].into();
    let mut resolver = async_dot::Resolver::new(cloudflare_dns, tls_config);

    let name = "gmail.com";
    let result = resolver.lookup_mail(name).await.unwrap();

    // the resolver keeps a TLS connection open until you explicitely close it.
    resolver.disconnect();
    // once disconnected, it may reconnect the next time you look something up.

    for data in result {
        println!("- Mail Exchange: {:?} (P={})", data.host, data.preference);
    }
};

block_on(task);
```

## Crate Features

- supports `A`, `AAAA`, `MX`, `NS` and `TXT` records.
- async-only API (can be made synchronous using futures_lite::block_on)
- the `Resolver` has an internal TTL-based cache

## TLS Cryptography Backend

By default, this crate selects `aws-lc-rs` as a cryptographic backend in rustls.

To select a different cryptography backend for `rustls`:
- disable default features for your `async-dns` dependency
- add `rustls` as a direct dependency of your project
- enable the features you want in your `rustls` dependency
