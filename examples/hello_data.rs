// hello_data.rs - exampl
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

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response};
use simple_hyper_server_tls::*;
use std::{convert::Infallible, net::SocketAddr};
use tokio;

async fn handle(_: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new("Hello, World!".into()))
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let make_svc = make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle)) });
    #[cfg(not(target_os = "windows"))]
    const CERT: &[u8] = include_bytes!("../data/cert.pem");
    #[cfg(not(target_os = "windows"))]
    const KEY: &[u8] = include_bytes!("../data/key.pem");

    #[cfg(target_os = "windows")]
    const CERT: &[u8] = include_bytes!("..\\data\\cert.pem");
    #[cfg(target_os = "windows")]
    const KEY: &[u8] = include_bytes!("..\\data\\key.pem");
    let mut server = hyper_from_pem_data(CERT, KEY, Protocols::ALL, &addr)?.serve(make_svc);
    while let Err(e) = (&mut server).await {
        eprintln!("server error: {}", e);
    }
    Ok(())
}
