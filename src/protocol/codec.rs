use crate::protocol::sync::{SyncRequest, SyncResponse, MAX_SYNC_FRAME_BYTES};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use std::io;

#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

impl request_response::Codec for SyncCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        decode_bounded(io).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        decode_bounded(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        encode_bounded(io, &request).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        encode_bounded(io, &response).await
    }
}

async fn decode_bounded<T, V>(io: &mut T) -> io::Result<V>
where
    T: AsyncRead + Unpin + Send,
    V: for<'de> serde::Deserialize<'de>,
{
    let mut bytes = Vec::new();
    io.take((MAX_SYNC_FRAME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_SYNC_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let (value, trailing) = postcard::take_from_bytes(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed frame"))?;
    if !trailing.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "trailing bytes"));
    }
    Ok(value)
}

async fn encode_bounded<T, V>(io: &mut T, value: &V) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    V: serde::Serialize,
{
    let bytes = postcard::to_allocvec(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encode failed"))?;
    if bytes.len() > MAX_SYNC_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    io.write_all(&bytes).await?;
    io.close().await
}
