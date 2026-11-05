//! 客户端 TLS 配置与握手（全项目统一使用 rustls）
//!
//! 项目中有三处需要"以 TLS 客户端身份"握手：
//! 1. `test-proxy` 自检客户端连接 **HTTPS 代理**（代理多为自签证书，始终跳过校验）；
//! 2. `test-proxy` 经 CONNECT 隧道连接 **目标站点**（系统根证书，严格校验）；
//! 3. 路径前缀直连模式的 **上游 HTTPS**（默认系统根证书，`insecure_tls` 才跳过）。
//!
//! 三者共用本模块，避免出现"服务端 rustls + 客户端 native-tls"两套根证书来源与
//! 两棵依赖树。默认路径的系统根证书来自 `rustls-native-certs`（Windows 证书库 /
//! macOS Keychain / Linux 常见 CA bundle），与 native-tls 读取的是同一份系统信任库。
//!
//! **insecure 的安全边界**：自定义校验器只跳过"证书链与主机名校验"，握手签名仍由
//! rustls 的密码学后端验证（对端必须持有证书对应的私钥），不是对整个 TLS 握手放行。
//! 这条路径只应由用户显式开启（`--proxy-insecure` / `path_proxy_insecure_tls`）。

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// 构建客户端 TLS 配置
///
/// - `insecure = false`：加载系统根证书并严格校验证书链与主机名；**一个根证书都
///   加载不到时直接报错**（环境不支持就终止，而不是静默降级为"不校验"）。
/// - `insecure = true`：使用 [`InsecureVerifier`]，跳过链与主机名校验。
pub fn build_client_config(insecure: bool) -> Result<Arc<ClientConfig>> {
    if insecure {
        let provider = default_crypto_provider();
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier { provider }))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        log::debug!(
            "Some system root certificates could not be loaded: {} error(s)",
            native.errors.len()
        );
    }

    let mut roots = rustls::RootCertStore::empty();
    for cert in native.certs {
        // 个别损坏的系统证书不应让整个客户端不可用；但"一个都没有"必须报错
        if let Err(e) = roots.add(cert) {
            log::debug!("Skipping invalid system root certificate: {}", e);
        }
    }
    if roots.is_empty() {
        anyhow::bail!(
            "No system root certificates available: cannot verify TLS peers. \
             Install a system CA bundle or use an explicit insecure mode."
        );
    }

    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// 返回进程默认密码学后端；未显式安装时用 rustls 的编译期默认（aws-lc-rs）
fn default_crypto_provider() -> Arc<CryptoProvider> {
    match CryptoProvider::get_default() {
        Some(p) => p.clone(),
        None => Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    }
}

/// 在已有流上完成客户端 TLS 握手
///
/// `server_name` 用于 SNI 与主机名校验；IPv6 字面量允许带方括号（自动剥离）。
/// 握手整体受 `timeout` 约束，避免半开连接把客户端挂死。
pub async fn connect_tls<S>(
    stream: S,
    server_name: &str,
    insecure: bool,
    timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let normalized = server_name
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(server_name);
    let name = ServerName::try_from(normalized.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid TLS server name: {}", server_name))?;

    let connector = tokio_rustls::TlsConnector::from(build_client_config(insecure)?);
    tokio::time::timeout(timeout, connector.connect(name, stream))
        .await
        .context("TLS handshake timed out")?
        .context("TLS handshake failed")
}

/// "接受任意证书"的校验器：仅跳过链校验与主机名校验
///
/// 仍复用 rustls 的 `verify_tls1x_signature`，确保证书私钥确实参与了握手；
/// `supported_verify_schemes` 与默认后端保持一致，避免因为算法列表不同而
/// 与正常路径产生额外的握手协商差异。
struct InsecureVerifier {
    provider: Arc<CryptoProvider>,
}

// `CryptoProvider` 不保证实现 Debug，手写以避免把内部结构带进日志
impl std::fmt::Debug for InsecureVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InsecureVerifier")
    }
}

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_client_config_insecure_succeeds() {
        assert!(build_client_config(true).is_ok());
    }

    /// 默认路径必须真的加载到系统根证书：这是"严格校验可用"的环境前提，
    /// 也是启动/自检时的环境检查（加载不到就报错而非降级）。
    #[test]
    fn test_build_client_config_secure_loads_system_roots() {
        let config = build_client_config(false);
        assert!(
            config.is_ok(),
            "系统根证书不可用时应报错而不是降级为不校验：{:?}",
            config.err()
        );
    }
}
