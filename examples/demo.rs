use futures_lite::future::block_on;
use async_dot::*;

use std::sync::Arc;

fn main() {
    let roots = webpki_roots::TLS_SERVER_ROOTS.iter().cloned();
    let root_store = rustls::RootCertStore::from_iter(roots);

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let tls_config = Arc::new(tls_config);

    let task = async {
        let dot_server_ip = [1; 4].into();
        let mut resolver = Resolver::new(dot_server_ip, tls_config);

        let name = "gmail.com";

        for data in resolver.lookup_ipv4(name).await.unwrap() {
            println!("- IPv4 {:?}", data);
        }

        for data in resolver.lookup_ipv6(name).await.unwrap() {
            println!("- IPv6 {:?}", data);
        }

        resolver.disconnect();

        for data in resolver.lookup_cname(name).await.unwrap() {
            println!("- CNAME {:?}", data);
        }

        for data in resolver.lookup_mail(name).await.unwrap() {
            println!("- Mail Exchange: {:?} (P={})", data.host, data.preference);
        }

        for data in resolver.lookup_txt(name).await.unwrap() {
            println!("- Text {:?}", data);
        }

        for data in resolver.lookup_ns(name).await.unwrap() {
            println!("- NS {:?}", data);
        }

        resolver.disconnect();
    };

    block_on(task);
}