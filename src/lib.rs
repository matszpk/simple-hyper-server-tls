// lib.rs - main library
//
// simple-hyper-server-tls - Library to simplify initialization TLS for hyper server
// Copyright (C) 2022  Mateusz Szpakowski
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

#![cfg_attr(docsrs, feature(doc_cfg))]
//! The library to simplify TLS configuration for Hyper server including ALPN
//! (Application-Layer Protocol Negotiation) setup.
//! This library setup TLS configuration suitable for clients.
//! The configuration includes the HTTP protocol choice setup (ALPN mechanism setup)
//! thanks to the almost clients can choose for example HTTP/2 protocol.
//!
//! The usage of this library requires choose suitable the TLS implementation, by choosing
//! feature that one of:
//! * `tls-rustls` - RusTLS - native for Rust TLS implementation based on tokio-rustls,
//! * `tls-openssl` - OpenSSL - TLS implementation based native OpenSSL library and openssl.
//!
//! The `tls-openssl` is recommended for systems which can not handle rustls
//! due to some problems, like lacks of some CPU instructions needed by `ring` crate.
//! For other systems, `tls-rustls` should be preferred.
//!
//! By default two versions of protocols is enabled (HTTP/1.0, HTTP/1.1, HTTP/2).
//! It is possible to choose only one version by disabling default features and choose
//! one of features:
//! * `hyper-h1` - for HTTP/1.0 or HTTP/1.1,
//! * `hyper-h2` - for HTTP/2.
//!
//! ## List of other features
//! * `hyper-full-server` - enables all features for hyper server.
//!
//! ## Examples
//! The simplest usage is:
//!
//! ```no_run
//! use std::{convert::Infallible, net::SocketAddr};
//! use simple_hyper_server_tls::*;
//! use hyper::{Body, Request, Response, Server};
//! use hyper::service::{make_service_fn, service_fn};
//! 
//! async fn handle(_: Request<Body>) -> Result<Response<Body>, Infallible> {
//!     Ok(Response::new("Hello, World!".into()))
//! }
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
//! 
//!     let make_svc = make_service_fn(|_conn| async {
//!         Ok::<_, Infallible>(service_fn(handle))
//!     });
//!     let mut server = hyper_from_pem_files("cert.pem", "key.pem", Protocols::ALL, &addr)?
//!             .serve(make_svc);
//!     while let Err(e) = (&mut server).await {
//!         eprintln!("server error: {}", e);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! Additional functions can be used for customization of the TLS configuration.

use std::path::Path;
use std::net::SocketAddr;
#[cfg(feature = "tls-rustls")]
use rustls::ServerConfig;
#[cfg(feature = "tls-rustls")]
use rustls_pemfile;
#[cfg(feature = "tls-rustls")]
use tokio_rustls::rustls::{Certificate, PrivateKey};
#[cfg(feature = "tls-rustls")]
use tokio_rustls::TlsAcceptor;
#[cfg(feature = "tls-openssl")]
use openssl::ssl::{SslContext, SslContextBuilder, SslFiletype, SslMethod, SslRef};
#[cfg(feature = "tls-openssl")]
use openssl::x509::X509;
#[cfg(feature = "tls-openssl")]
use openssl::pkey::PKey;
use hyper::server::{Server, Builder};
use hyper::server::conn::AddrIncoming;
#[cfg(any(feature = "tls-rustls", feature = "tls-openssl"))]
use tls_listener::hyper::WrappedAccept;

#[cfg(feature = "tls-rustls")]
pub use rustls;
#[cfg(feature = "tls-openssl")]
pub use openssl;
#[cfg(any(feature = "tls-rustls", feature = "tls-openssl"))]
pub use tls_listener;
pub use hyper;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Defines protocols that will be used in TLS configuration.
pub enum Protocols {
    /// All protocols enabled by features (HTTP/1.1, HTTP/2).
    ALL,
    #[cfg(feature = "hyper-h1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hyper-h1")))]
    /// Only HTTP1.0 or HTTP/1.1 if enabled by hyper-h1.
    HTTP1,
    #[cfg(feature = "hyper-h2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hyper-h2")))]
    /// Only HTTP/2 if enabled by hyper-h2.
    HTTP2,
}

/// Boxed error type.
pub type Error = Box<dyn std::error::Error>;

#[cfg(feature = "tls-rustls")]
fn rustls_server_config_from_readers<R: std::io::Read>(cert: R, key: R,
                protocols: Protocols) -> Result<ServerConfig, Error> {
    use std::io::{self, BufReader};
    // load certificates and keys from Read
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert))
            .map(|mut certs| certs.drain(..).map(Certificate).collect())?;
    let mut keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(
            &mut BufReader::new(key))
            .map(|mut keys| keys.drain(..).map(PrivateKey).collect())?;
    let mut config = ServerConfig::builder().with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(certs, keys.remove(0))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    
    // set up ALPN protocols based on Protocols
    config.alpn_protocols = match protocols {
        #[cfg(all(feature = "hyper-h1", feature = "hyper-h2"))]
        Protocols::ALL => vec![ b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec() ],
        
        #[cfg(all(feature = "hyper-h1", not(feature = "hyper-h2")))]
        Protocols::ALL => vec![ b"http/1.1".to_vec(), b"http/1.0".to_vec() ],
        
        #[cfg(all(not(feature = "hyper-h1"), feature = "hyper-h2"))]
        Protocols::ALL => vec![ b"h2".to_vec() ],
        
        #[cfg(feature = "hyper-h1")]
        Protocols::HTTP1 => vec![ b"http/1.1".to_vec(), b"http/1.0".to_vec() ],
        #[cfg(feature = "hyper-h2")]
        Protocols::HTTP2 => vec![ b"h2".to_vec() ],
    };
    Ok(config)
}

#[cfg(feature = "tls-rustls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls-rustls")))]
/// The low-level function to retrieve configuration to further customization.
///
/// Creates the RusTLS server configuration. Certificate and key will be obtained from files.
/// Protocols determines list of protocols that will be supported.
pub fn rustls_server_config_from_pem_files<P: AsRef<Path>>(cert_file: P, key_file: P,
                protocols: Protocols) -> Result<ServerConfig, Error> {
    use std::fs::File;
    rustls_server_config_from_readers(File::open(cert_file)?, File::open(key_file)?,
                    protocols)
}

#[cfg(feature = "tls-rustls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls-rustls")))]
/// The low-level function to retrieve configuration to further customization.
///
/// Creates the RusTLS server configuration. Certificate and key will be obtained from data.
/// Protocols determines list of protocols that will be supported.
pub fn rustls_server_config_from_pem_data<'a>(cert: &'a [u8], key: &'a [u8],
                protocols: Protocols) -> Result<ServerConfig, Error> {
    rustls_server_config_from_readers(cert, key, protocols)
}

#[cfg(feature = "tls-openssl")]
fn ssl_context_set_alpns(builder: &mut SslContextBuilder, protocols: Protocols)
             -> Result<(), Error> {
    // set up ALPN protocols based on Protocols
    let protos = match protocols {
        #[cfg(all(feature = "hyper-h1", feature = "hyper-h2"))]
        Protocols::ALL => &b"\x02h2\x08http/1.1\x08http/1.0"[..],
        
        #[cfg(all(feature = "hyper-h1", not(feature = "hyper-h2")))]
        Protocols::ALL => &b"\x08http/1.1\x08http/1.0"[..],
        
        #[cfg(all(not(feature = "hyper-h1"), feature = "hyper-h2"))]
        Protocols::ALL => &b"\x02h2"[..],
        
        #[cfg(feature = "hyper-h1")]
        Protocols::HTTP1 => &b"\x08http/1.1\x08http/1.0"[..],
        #[cfg(feature = "hyper-h2")]
        Protocols::HTTP2 => &b"\x02h2"[..],
    };
    builder.set_alpn_protos(protos)?;
    // set uo ALPN selection routine - as select_next_proto
    builder.set_alpn_select_callback(move |_: &mut SslRef, list: &[u8]| {
            openssl::ssl::select_next_proto(protos, list).ok_or(
                    openssl::ssl::AlpnError::NOACK)
    });
    Ok(())
}

#[cfg(feature = "tls-openssl")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls-openssl")))]
/// The low-level function to retrieve configuration to further customization.
///
/// Creates the SSL context builder. Certificate and key will be obtained from files.
/// Protocols determines list of protocols that will be supported.
pub fn ssl_context_builder_from_pem_files<P: AsRef<Path>>(cert_file: P, key_file: P,
                protocols: Protocols) -> Result<SslContextBuilder, Error> {
    let mut builder = SslContext::builder(SslMethod::tls_server()).unwrap();
    builder.set_certificate_file(cert_file, SslFiletype::PEM)?;
    builder.set_private_key_file(key_file, SslFiletype::PEM)?;
    ssl_context_set_alpns(&mut builder, protocols)?;
    Ok(builder)
}

#[cfg(feature = "tls-openssl")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls-openssl")))]
/// The low-level function to retrieve configuration to further customization.
///
/// Creates the SSL context builder. Certificate and key will be obtained from data.
/// Protocols determines list of protocols that will be supported.
pub fn ssl_context_builder_from_pem_data<'a>(cert: &'a [u8], key: &'a [u8],
                protocols: Protocols) -> Result<SslContextBuilder, Error> {
    let mut builder = SslContext::builder(SslMethod::tls_server()).unwrap();
    builder.set_certificate(X509::from_pem(cert)?.as_ref())?;
    builder.set_private_key(PKey::private_key_from_pem(key)?.as_ref())?;
    ssl_context_set_alpns(&mut builder, protocols)?;
    Ok(builder)
}

#[cfg(feature = "tls-rustls")]
/// TlsListener for hyper server.
pub type TlsListener = tls_listener::TlsListener<WrappedAccept<AddrIncoming>, TlsAcceptor>;
#[cfg(all(not(docsrs), feature = "tls-openssl"))]
/// TlsListener for hyper server.
pub type TlsListener = tls_listener::TlsListener<WrappedAccept<AddrIncoming>, SslContext>;

/// The higher level function. Creates the TLS listener for Hyper server.
///
/// Certificate and key will be obtained from files.
/// Protocols determines list of protocols that will be supported.
/// Typical usage is:
/// ```no run
/// let listener = listener_from_pem_files("cert.pem", "key.pem", Protocols::ALL, &addr)?;
/// let server = Server::builder(listener).serve(make_svc);
/// ```
pub fn listener_from_pem_files<P: AsRef<Path>>(cert_file: P, key_file: P,
                protocols: Protocols, addr: &SocketAddr) -> Result<TlsListener, Error> {
    #[cfg(feature = "tls-rustls")]
    let acceptor = {
        use std::sync::Arc;
        let config = rustls_server_config_from_pem_files(cert_file, key_file, protocols)?;
        TlsAcceptor::from(Arc::new(config))
    };
    #[cfg(feature = "tls-openssl")]
    let acceptor = {
        let builder = ssl_context_builder_from_pem_files(cert_file, key_file, protocols)?;
        builder.build()
    };
    Ok(TlsListener::new_hyper(acceptor, AddrIncoming::bind(addr)?))
}

/// The higher level function. Creates the TLS listener for Hyper server.
///
///Certificate and key will be obtained from data.
/// Protocols determines list of protocols that will be supported.
/// Typical usage is:
/// ```no run
/// let listener = listener_from_pem_data(cert_data, key_data, Protocols::ALL, &addr)?;
/// let server = Server::builder(listener).serve(make_svc);
/// ```
pub fn listener_from_pem_data<'a>(cert: &'a [u8], key: &'a [u8],
                protocols: Protocols, addr: &SocketAddr) -> Result<TlsListener, Error> {
    #[cfg(feature = "tls-rustls")]
    let acceptor = {
        use std::sync::Arc;
        let config = rustls_server_config_from_pem_data(cert, key, protocols)?;
        TlsAcceptor::from(Arc::new(config))
    };
    #[cfg(feature = "tls-openssl")]
    let acceptor = {
        let builder = ssl_context_builder_from_pem_data(cert, key, protocols)?;
        builder.build()
    };
    Ok(TlsListener::new_hyper(acceptor, AddrIncoming::bind(&addr)?))
}

/// The highest level function. Creates the Hyper server builder.
///
///Certificate and key will be obtained from files.
/// Protocols determines list of protocols that will be supported.
/// Typical usage is:
/// ```no run
/// let server = hyper_from_pem_files("cert.pem", "key.pem", Protocols::ALL, &addr)?
///             .serve(make_svc);
/// ```
pub fn hyper_from_pem_files<P: AsRef<Path>>(cert_file: P, key_file: P, protocols: Protocols,
                addr: &SocketAddr) -> Result<Builder<TlsListener>, Error> {
    let listener = listener_from_pem_files(cert_file, key_file, protocols, addr)?;
    let builder = Server::builder(listener);
    Ok(match protocols {
        Protocols::ALL => builder,
        #[cfg(feature = "hyper-h1")]
        Protocols::HTTP1 => builder.http1_only(true),
        #[cfg(feature = "hyper-h2")]
        Protocols::HTTP2 => builder.http2_only(true),
    })
}

/// The highest level function. Creates the Hyper server builder.
///
/// Certificate and key will be obtained from data.
/// Protocols determines list of protocols that will be supported.
/// Typical usage is:
/// ```no run
/// let server = hyper_from_pem_data(cert_data, key_data, Protocols::ALL, &addr)?
///             .serve(make_svc);
/// ```
pub fn hyper_from_pem_data<'a>(cert: &'a [u8], key: &'a [u8], protocols: Protocols,
                addr: &SocketAddr) -> Result<Builder<TlsListener>, Error> {
    let listener = listener_from_pem_data(cert, key, protocols, addr)?;
    let builder = Server::builder(listener);
    Ok(match protocols {
        Protocols::ALL => builder,
        #[cfg(feature = "hyper-h1")]
        Protocols::HTTP1 => builder.http1_only(true),
        #[cfg(feature = "hyper-h2")]
        Protocols::HTTP2 => builder.http2_only(true),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "tls-rustls")]
    fn test_rustls_server_config_from_readers() {
        use super::*;
        const CERT: &[u8] = include_bytes!("../data/cert.pem");
        const KEY: &[u8] = include_bytes!("../data/key.pem");
        let config = rustls_server_config_from_readers(CERT, KEY, Protocols::ALL).unwrap();
        #[cfg(all(feature = "hyper-h1", feature = "hyper-h2"))]
        assert_eq!(config.alpn_protocols, vec![ b"h2".to_vec(), b"http/1.1".to_vec(),
                                        b"http/1.0".to_vec() ]);
        #[cfg(all(not(feature = "hyper-h1"), feature = "hyper-h2"))]
        assert_eq!(config.alpn_protocols, vec![ b"h2".to_vec() ]);
        #[cfg(all(feature = "hyper-h1", not(feature = "hyper-h2")))]
        assert_eq!(config.alpn_protocols, vec![ b"http/1.1".to_vec(), b"http/1.0".to_vec() ]);
        
        #[cfg(feature = "hyper-h1")]
        {
            let config = rustls_server_config_from_readers(CERT, KEY,
                            Protocols::HTTP1).unwrap();
            assert_eq!(config.alpn_protocols, vec![ b"http/1.1".to_vec(),
                                        b"http/1.0".to_vec() ]);
        }
        #[cfg(feature = "hyper-h2")]
        {
            let config = rustls_server_config_from_readers(CERT, KEY,
                            Protocols::HTTP2).unwrap();
            assert_eq!(config.alpn_protocols, vec![ b"h2".to_vec() ]);
        }
    }
}
