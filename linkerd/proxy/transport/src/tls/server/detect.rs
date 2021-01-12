use super::client_hello::{parse_sni, Sni};
use crate::{
    io::{self, AsyncReadExt},
    Detect,
};
use bytes::BytesMut;
use linkerd_error::Error;
use tracing::{debug, trace};

#[derive(Copy, Clone, Debug, Default)]
pub struct DetectSni(());

#[async_trait::async_trait]
impl Detect for DetectSni {
    type Protocol = Sni;

    async fn detect<I: io::AsyncRead + Send + Unpin + 'static>(
        &self,
        io: &mut I,
        buf: &mut BytesMut,
    ) -> Result<Option<Sni>, Error> {
        loop {
            if buf.capacity() == 0 {
                debug!("Buffer exhausted before SNI");
                return Ok(None);
            }

            let sz = io.read_buf(buf).await?;
            if sz == 0 {
                debug!("Socket closed before SNI");
                return Ok(None);
            }

            trace!(read = sz, buf = buf.len(), "Reading SNI");
            if let Ok(sni) = parse_sni(&buf[..]) {
                debug!(?sni, "Parsed SNI");
                return Ok(sni);
            }
        }
    }
}
