use hyper::{
    service::{make_service_fn, service_fn},
    Server,
};
use std::{convert::Infallible, net::SocketAddr};
use ws::web_socket;

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 9001));
    let server = Server::bind(&addr).serve(make_service_fn(|_| async {
        Ok::<_, Infallible>(service_fn(web_socket))
    }));

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
