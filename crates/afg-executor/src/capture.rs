//! Bounded output capture with hashing and optional forwarding.

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Captured, sha256_hex};

/// Read `src` to EOF. Keep the first `limit` bytes, hash everything, and
/// forward everything to `tee` if one is given.
pub async fn capture<R, W>(
    mut src: R,
    limit: usize,
    mut tee: Option<W>,
) -> std::io::Result<Captured>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut kept = Vec::new();
    let mut total: u64 = 0;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        hasher.update(chunk);
        total += n as u64;
        if kept.len() < limit {
            let take = (limit - kept.len()).min(n);
            kept.extend_from_slice(&chunk[..take]);
        }
        if let Some(t) = tee.as_mut() {
            // A closed terminal must not kill the run; stop forwarding instead.
            if t.write_all(chunk).await.is_err() || t.flush().await.is_err() {
                tee = None;
            }
        }
    }
    Ok(Captured {
        truncated: total > kept.len() as u64,
        bytes: kept,
        total_len: total,
        sha256: sha256_hex(&hasher.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn truncates_but_hashes_everything() {
        let data = b"hello world".to_vec();
        let c = capture(&data[..], 5, None::<tokio::io::Sink>)
            .await
            .unwrap();
        assert_eq!(c.bytes, b"hello");
        assert!(c.truncated);
        assert_eq!(c.total_len, 11);
        let full = capture(&data[..], 100, None::<tokio::io::Sink>)
            .await
            .unwrap();
        assert_eq!(c.sha256, full.sha256);
        assert!(!full.truncated);
    }

    #[tokio::test]
    async fn tees() {
        let mut out = Vec::new();
        capture(&b"abc"[..], 1, Some(&mut out)).await.unwrap();
        assert_eq!(out, b"abc");
    }
}
