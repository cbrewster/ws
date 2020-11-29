#[derive(Debug)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Close,
}
