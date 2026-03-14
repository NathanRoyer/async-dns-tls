use futures_lite::future::block_on;
use async_dns_tls::*;
use std::env::args;
use std::sync::Arc;

fn main() {
    let arg_err_msg = "please provide a hostname as argument";
    let hostname = args().last().expect(arg_err_msg);

    if args().count() < 2 {
        panic!("{arg_err_msg}");
    }

    let roots = webpki_roots::TLS_SERVER_ROOTS.iter().cloned();
    let root_store = rustls::RootCertStore::from_iter(roots);

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let tls_config = Arc::new(tls_config);

    let task = async {
        let cloudflare_dns = [1, 1, 1, 1].into();
        let mut resolver = Resolver::new(cloudflare_dns, tls_config);

        match resolver.lookup_ipv4(&hostname).await {
            Ok(results) => for data in results {
                println!("- IPv4 {:?}", data);
            },
            Err(error) => println!("failed to get A records: {:?}", error),
        }

        match resolver.lookup_ipv6(&hostname).await {
            Ok(results) => for data in results {
                println!("- IPv6 {:?}", data);
            },
            Err(error) => println!("failed to get AAAA records: {:?}", error),
        }

        match resolver.lookup_cname(&hostname).await {
            Ok(results) => for data in results {
                println!("- CNAME {:?}", data);
            },
            Err(error) => println!("failed to get CNAME records: {:?}", error),
        }

        match resolver.lookup_mail(&hostname).await {
            Ok(results) => for data in results {
                println!("- Mail Exchange: {:?} (P={})", data.host, data.preference);
            },
            Err(error) => println!("failed to get MX records: {:?}", error),
        }

        match resolver.lookup_txt(&hostname).await {
            Ok(results) => for data in results {
                println!("- Text {:?}", data);
            },
            Err(error) => println!("failed to get TXT records: {:?}", error),
        }

        match resolver.lookup_ns(&hostname).await {
            Ok(results) => for data in results {
                println!("- NS {:?}", data);
            },
            Err(error) => println!("failed to get NS records: {:?}", error),
        }
    };

    block_on(task);
}