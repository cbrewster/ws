use hyper::{service::make_service_fn, Server};
use std::{convert::Infallible, net::SocketAddr};
use ws::{Message, WebSocketHandler};

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 9001));
    let server = Server::bind(&addr).serve(make_service_fn(|_| async {
        Ok::<_, Infallible>(WebSocketHandler::new(|mut ws| async move {
            while let Some(msg) = ws.recv().await {
                dbg!(ws.send(msg).await.ok());
                ws.send(Message::Binary(vec![0x1, 0x2, 0x3, 0x4]))
                    .await
                    .ok();
            }
        }))
    }));

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
