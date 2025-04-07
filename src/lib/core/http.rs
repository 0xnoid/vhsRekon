use reqwest::header::{HeaderMap, HeaderValue, HOST};
use rustls::{ClientConfig, RootCertStore};
use rustls::pki_types::ServerName;
use std::collections::HashSet;
use std::net::{TcpStream, ToSocketAddrs, IpAddr};
use std::sync::Arc;
use std::time::Duration;
use x509_parser::prelude::*;
use x509_parser::extensions::ParsedExtension;

#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    verbose: bool,
    verbose_callback: Option<Arc<Box<dyn Fn(&str) + Send + Sync>>>,
}

#[derive(Debug)]
pub struct VHostResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: String,
    pub content_length: usize,
    pub server: Option<String>,
    pub certificate_names: HashSet<String>,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
            verbose: false,
            verbose_callback: None,
        }
    }

    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    pub fn set_verbose_callback<F>(&mut self, callback: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.verbose_callback = Some(Arc::new(Box::new(callback)));
    }

    fn log_verbose(&self, message: &str) {
        if self.verbose {
            if let Some(ref callback) = self.verbose_callback {
                callback(message);
            } else {
                println!("{}", message);
            }
        }
    }

    fn detect_server(headers: &HeaderMap, body: &str) -> Option<String> {
        let server_header = headers.get("server").and_then(|h| h.to_str().ok());
        let powered_by = headers.get("x-powered-by").and_then(|h| h.to_str().ok());
        
        if let Some(server) = server_header {
            let server_lower = server.to_lowercase();

            if server_lower.contains("nginx") {
                if let Some(version) = server.split('/').nth(1) {
                    return Some(format!("NGINX/{}", version));
                }
                return Some("NGINX".to_string());
            }

            if server_lower.contains("apache") {
                if let Some(version) = server.split('/').nth(1) {
                    return Some(format!("Apache/{}", version));
                }
                return Some("Apache".to_string());
            }

            if server_lower.contains("iis") || server_lower.contains("microsoft-iis") {
                if let Some(version) = server.split('/').nth(1) {
                    return Some(format!("IIS/{}", version));
                }
                return Some("IIS".to_string());
            }

            if server_lower.contains("litespeed") {
                if let Some(version) = server.split('/').nth(1) {
                    return Some(format!("LiteSpeed/{}", version));
                }
                return Some("LiteSpeed".to_string());
            }

            if server_lower.contains("caddy") {
                if let Some(version) = server.split('/').nth(1) {
                    return Some(format!("Caddy/{}", version));
                }
                return Some("Caddy".to_string());
            }
        }

        if let Some(powered) = powered_by {
            let powered_lower = powered.to_lowercase();
            
            if powered_lower.contains("php") {
                if let Some(version) = powered.split('/').nth(1) {
                    return Some(format!("PHP/{}", version));
                }
                return Some("PHP".to_string());
            }

            if powered_lower.contains("node.js") || powered_lower.contains("nodejs") {
                if let Some(version) = powered.split('/').nth(1) {
                    return Some(format!("Node.js/{}", version));
                }
                return Some("Node.js".to_string());
            }

            if powered_lower.contains("express") {
                if let Some(version) = powered.split('/').nth(1) {
                    return Some(format!("Express/{}", version));
                }
                return Some("Express".to_string());
            }
        }

        if headers.contains_key("x-drupal-cache") {
            return Some("Drupal CMS".to_string());
        }
        if headers.contains_key("x-wordpress-cache") {
            return Some("WordPress CMS".to_string());
        }
        if headers.contains_key("x-generator") {
            if let Some(generator) = headers.get("x-generator").and_then(|h| h.to_str().ok()) {
                if generator.to_lowercase().contains("joomla") {
                    return Some("Joomla CMS".to_string());
                }
            }
        }

        let body_lower = body.to_lowercase();
        if body_lower.contains("wp-content") || body_lower.contains("wp-includes") {
            return Some("WordPress CMS".to_string());
        }
        if body_lower.contains("drupal.js") || body_lower.contains("drupal.min.js") {
            return Some("Drupal CMS".to_string());
        }
        if body_lower.contains("joomla!") || body_lower.contains("/joomla/") {
            return Some("Joomla CMS".to_string());
        }
        if body_lower.contains("laravel") {
            return Some("Laravel Framework".to_string());
        }
        if body_lower.contains("django") {
            return Some("Django Framework".to_string());
        }
        if body_lower.contains("flask") {
            return Some("Flask Framework".to_string());
        }
        if body_lower.contains("rails") {
            return Some("Ruby on Rails".to_string());
        }
        if body_lower.contains("spring-boot") || body_lower.contains("springboot") {
            return Some("Spring Boot".to_string());
        }

        let mut security_features = Vec::new();
        if headers.contains_key("x-frame-options") {
            security_features.push("X-Frame-Options");
        }
        if headers.contains_key("content-security-policy") {
            security_features.push("CSP");
        }
        if headers.contains_key("strict-transport-security") {
            security_features.push("HSTS");
        }

        if !security_features.is_empty() {
            return Some(format!("Server with {}", security_features.join(", ")));
        }

        Some("Unknown Server".to_string())
    }

    pub fn get_certificate_names(&self, ip: &str, port: u16) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
        let mut names = HashSet::new();
        let root_store = RootCertStore::empty();
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let ip_addr: IpAddr = ip.parse()?;
        let ip_std = rustls::pki_types::IpAddr::from(ip_addr);
        let server_name = ServerName::IpAddress(ip_std);
        
        if let Ok(stream) = TcpStream::connect(format!("{}:{}", ip, port)) {
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut conn = rustls::ClientConnection::new(
                Arc::new(config),
                server_name
            )?;
            
            let _ = rustls::Stream::new(&mut conn, &mut &stream);
            
            if let Some(certs) = conn.peer_certificates() {
                if let Some(cert_data) = certs.first() {
                    if let Ok((_, cert)) = X509Certificate::from_der(cert_data.as_ref()) {
                        if let Some(san_ext) = cert.extensions()
                            .iter()
                            .find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME) {
                            if let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
                                for name in san.general_names.iter() {
                                    if let GeneralName::DNSName(dns) = name {
                                        self.log_verbose(&format!("[+] Found SAN: {}", dns));
                                        names.insert(dns.to_string());
                                    }
                                }
                            }
                        }
                        
                        if let Some(cn) = cert.subject().iter_common_name().next() {
                            if let Ok(cn_str) = cn.as_str() {
                                self.log_verbose(&format!("[+] Found CN: {}", cn_str));
                                names.insert(cn_str.to_string());
                            }
                        }
                    }
                }
            }
        }
        
        Ok(names)
    }

    pub async fn validate_domain(&self, domain: &str, ip: &str, ports: &[u16]) -> bool {
        self.log_verbose(&format!("[*] Validating domain {} against IP {}", domain, ip));
        for port in ports {
            if let Ok(addrs) = format!("{}:{}", domain, *port).to_socket_addrs() {
                for addr in addrs {
                    if addr.ip().to_string() == ip {
                        self.log_verbose(&format!("[+] Domain {} resolves to target IP on port {}", domain, port));
                        return true;
                    }
                }
            }
        }
        self.log_verbose(&format!("[-] Domain {} does not resolve to target IP on any port", domain));
        false
    }

    pub async fn get_response(&self, ip: &str, port: u16, hostname: Option<&str>) -> Result<VHostResponse, Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        if let Some(host) = hostname {
            headers.insert(HOST, HeaderValue::from_str(host)?);
            self.log_verbose(&format!("[*] Checking host: {} on port {}", host, port));
        }
    
        let scheme = if port == 443 { "https" } else { "http" };
        let url = format!("{}://{}:{}", scheme, ip, port);
        
        let response = self.client
            .get(url)
            .headers(headers)
            .send()
            .await?;
    
        self.log_verbose(&format!("[+] Got response: {} for {} on port {}", 
            response.status(), 
            hostname.unwrap_or("baseline"),
            port
        ));

        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await?;
        let content_length = body.len();
        let server = Self::detect_server(&headers, &body);
        let mut certificate_names = HashSet::new();
        
        if port == 443 {
            if let Ok(names) = self.get_certificate_names(ip, port) {
                certificate_names = names;
            }
        }
        
        Ok(VHostResponse {
            status,
            headers,
            body,
            content_length,
            server,
            certificate_names,
        })
    }

    pub async fn get_baseline(&self, ip: &str, port: u16) -> Result<VHostResponse, Box<dyn std::error::Error>> {
        self.get_response(ip, port, None).await
    }

    pub async fn check_virtual_host(&self, ip: &str, port: u16, hostname: &str) -> Result<VHostResponse, Box<dyn std::error::Error>> {
        self.get_response(ip, port, Some(hostname)).await
    }
}