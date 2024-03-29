# Simple Hyper Server TLS

[![LGPL 2.1 License](https://img.shields.io/badge/License-LGPL--2.1-brightgreen)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)
[![Crate version](https://img.shields.io/crates/v/simple-hyper-server-tls)](https://crates.io/crates/simple-hyper-server-tls)
[![Docs](https://docs.rs/simple-hyper-server-tls/badge.svg)](https://docs.rs/simple-hyper-server-tls)

The library to simplify TLS configuration for Hyper server including ALPN
(Application-Layer Protocol Negotiation) setup.
This library setup TLS configuration suitable for clients.
The configuration includes the HTTP protocol choice setup (ALPN mechanism setup)
thanks to the almost clients can choose for example HTTP/2 protocol.

The usage of this library requires choose suitable the TLS implementation, by choosing
feature that one of:
* `tls-rustls` - RusTLS - native for Rust TLS implementation based on tokio-rustls,
* `tls-openssl` - OpenSSL - TLS implementation based native OpenSSL library and openssl.

The `tls-openssl` is recommended for systems which can not handle rustls
due to some problems, like lacks of some CPU instructions needed by `ring` crate.
For other systems, `tls-rustls` should be preferred.

By default three versions of HTTP protocol are enabled (HTTP/1.0, HTTP/1.1, HTTP/2).
It is possible to choose only one version by disabling default features and choose
one of features:
* `hyper-h1` - for HTTP/1.0 or HTTP/1.1,
* `hyper-h2` - for HTTP/2.

## List of other features
* `hyper-full-server` - enables all features for hyper server.

## Examples
The simplest usage is:

```no_run
use std::{convert::Infallible, net::SocketAddr};
use simple_hyper_server_tls::*;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};

async fn handle(_: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new("Hello, World!".into()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle))
    });
    let mut server = hyper_from_pem_files("cert.pem", "key.pem", Protocols::ALL, &addr)?
            .serve(make_svc);
    while let Err(e) = (&mut server).await {
        eprintln!("server error: {}", e);
    }
    Ok(())
}
```

Additional functions can be used for customization of the TLS configuration.
