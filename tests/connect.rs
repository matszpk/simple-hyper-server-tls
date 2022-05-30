// connect.rs - connection test
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

use std::{convert::Infallible, net::SocketAddr};
use tokio;
use tokio::sync::oneshot::{channel, Receiver};
use simple_hyper_server_tls::*;
use hyper::{Body, Request, Response};
use hyper::service::{make_service_fn, service_fn};
use futures::Future;
use reqwest::{Client, Version};
use reqwest::tls::Certificate;

const CERT: &[u8] = include_bytes!("../data/cert.pem");
const KEY: &[u8] = include_bytes!("../data/key.pem");

async fn handle(_: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new("Hello, World!".into()))
}

async fn make_server(port: u16, protos: Protocols, rx: Receiver<()>)
        -> impl Future<Output = Result<(), hyper::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle))
    });
    let server = hyper_from_pem_data(CERT, KEY, protos, &addr).unwrap()
                    .serve(make_svc);
    let graceful = server.with_graceful_shutdown(async move { rx.await.unwrap() });
    graceful
}

#[tokio::test]
async fn test_http2_connect_proto_all() {
    let (tx, rx) = channel();
    let future = make_server(3000, Protocols::ALL, rx).await;
    
    tokio::spawn(async move {future.await.unwrap(); });
    
    let client = Client::builder().add_root_certificate(
                    Certificate::from_pem(CERT).unwrap()).build().unwrap();
    let resp = client.get("https://localhost:3000/").send().await.unwrap();
    #[cfg(feature = "hyper-h2")]
    assert_eq!(Version::HTTP_2, resp.version());
    #[cfg(not(feature = "hyper-h2"))]
    assert_eq!(Version::HTTP_11, resp.version());
    
    tx.send(()).unwrap();
}

#[tokio::test]
#[cfg(feature = "hyper-h2")]
async fn test_http2_connect_proto_http2() {
    let (tx, rx) = channel();
    let future = make_server(3001, Protocols::HTTP2, rx).await;
    
    tokio::spawn(async move {future.await.unwrap(); });
    
    let client = Client::builder().add_root_certificate(
                    Certificate::from_pem(CERT).unwrap()).build().unwrap();
    let resp = client.get("https://localhost:3001/").send().await.unwrap();
    assert_eq!(Version::HTTP_2, resp.version());
    
    tx.send(()).unwrap();
}

#[tokio::test]
#[cfg(feature = "hyper-h1")]
async fn test_http2_connect_proto_http1() {
    let (tx, rx) = channel();
    let future = make_server(3002, Protocols::HTTP1, rx).await;
    
    tokio::spawn(async move {future.await.unwrap(); });
    
    let client = Client::builder().add_root_certificate(
                    Certificate::from_pem(CERT).unwrap()).build().unwrap();
    let resp = client.get("https://localhost:3002/").send().await.unwrap();
    assert_eq!(Version::HTTP_11, resp.version());
    
    tx.send(()).unwrap();
}
