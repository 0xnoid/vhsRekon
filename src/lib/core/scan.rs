use crate::lib::core::http::{HttpClient, VHostResponse};
use futures::stream::{self, StreamExt};
use similar::{ChangeTag, TextDiff};
use std::collections::{HashSet, HashMap};
use reqwest::header::HeaderMap;
use std::sync::Arc;
use indicatif::{ProgressBar, ProgressStyle};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use regex::Regex;

const SIMILARITY_THRESHOLD: f64 = 0.95;
const CONTENT_LENGTH_THRESHOLD: f64 = 0.05;
const DEFAULT_CONCURRENT: usize = 100;
const DYNAMIC_PATTERN_THRESHOLD: f64 = 0.7;
const MIN_SECTION_LENGTH: usize = 50;
const DEFAULT_PORTS: &[u16] = &[80, 443];

const SECTION_WEIGHTS: [(f64, &str); 4] = [
    (2.0, "header"),
    (1.5, "navigation"),
    (1.0, "main"),
    (0.5, "footer"),
];

#[derive(Debug, Clone)]
struct ContentPattern {
    pattern_type: String,
    count: usize,
}

#[derive(Debug, Clone)]
struct ContentSection {
    hash: u64,
    content_type: String,
    is_dynamic: bool,
}

#[derive(Debug, Clone)]
struct ContentAnalysis {
    full_hash: u64,
    sections: Vec<ContentSection>,
    dynamic_patterns: Vec<ContentPattern>,
    is_catchall: bool,
    is_dynamic_catchall: bool,
    confidence: f64,
}

#[derive(Debug, Clone)]
struct DynamicContentInfo {
    pattern_type: String,
    pattern: Regex,
}

pub struct Scanner {
    client: Arc<HttpClient>,
    max_concurrent: usize,
    verbose: bool,
    domain: Option<String>,
    ports: Vec<u16>,
    progress: Option<Arc<ProgressBar>>,
    content_hashes: Arc<tokio::sync::Mutex<HashMap<u64, usize>>>,
    section_hashes: Arc<tokio::sync::Mutex<HashMap<u64, usize>>>,
    pattern_frequencies: Arc<tokio::sync::Mutex<HashMap<String, usize>>>,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub hostname: String,
    pub port: u16,
    pub status_code: u16,
    pub content_length: usize,
    pub server: Option<String>,
    pub similarity: f64,
    pub is_distinct: bool,
    pub validation_method: String,
}

#[derive(Debug)]
pub struct AdvancedScanResult {
    pub hostname: String,
    pub port: u16,
    pub status_code: u16,
    pub content_length: usize,
    pub server: Option<String>,
    pub similarity: f64,
    pub is_distinct: bool,
    pub validation_method: String,
    pub is_catchall: bool,
    pub is_dynamic_catchall: bool,
    pub dynamic_confidence: f64,
    pub detected_patterns: Vec<String>,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            client: Arc::new(HttpClient::new()),
            max_concurrent: DEFAULT_CONCURRENT,
            verbose: false,
            domain: None,
            ports: DEFAULT_PORTS.to_vec(),
            progress: None,
            content_hashes: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            section_hashes: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            pattern_frequencies: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub fn set_ports(&mut self, ports: Vec<u16>) {
        self.ports = ports;
    }

    pub fn set_max_concurrent(&mut self, max: usize) {
        self.max_concurrent = max;
    }

    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
        Arc::get_mut(&mut self.client).unwrap().set_verbose(verbose);
    }

    pub fn set_verbose_callback<F>(&mut self, callback: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        Arc::get_mut(&mut self.client).unwrap().set_verbose_callback(callback);
    }

    pub fn set_domain(&mut self, domain: String) {
        self.domain = Some(domain);
    }

    fn get_fqdn(&self, hostname: &str) -> String {
        if let Some(ref domain) = self.domain {
            if !hostname.contains('.') {
                format!("{}.{}", hostname, domain)
            } else {
                hostname.to_string()
            }
        } else {
            hostname.to_string()
        }
    }

    pub async fn scan_basic(&mut self, ip: &str, hostnames: Vec<String>) -> Vec<ScanResult> {
        let mut results = Vec::new();
        let mut any_port_succeeded = false;
        let ip_ref = ip.to_string();
        
        let total_ports = self.ports.len();
        let total_items = hostnames.len();
        let total_operations = total_ports * total_items;
    
        let pb = ProgressBar::new(total_operations as u64);
        pb.set_style(ProgressStyle::with_template(" {spinner:.cyan} [{bar:50.cyan/blue}] {pos}/{len} ({percent}%) [{elapsed_precise}] - {msg}")
            .unwrap()
            .progress_chars("█▓▒░")
            .tick_chars("⠋⠙⠚⠞⠖⠦⠴⠲⠳⠓"));
        pb.set_message(format!("IP: {}", ip));
        self.progress = Some(Arc::new(pb));

        for port in &self.ports {
            let baseline = match self.client.get_baseline(ip, *port).await {
                Ok(response) => response,
                Err(_) => {
                    if self.verbose {
                        eprintln!("[-] Failed to get baseline response from {}:{}", ip, port);
                    }
                    continue;
                }
            };

            any_port_succeeded = true;
            let mut all_hostnames: HashSet<String> = hostnames.iter()
                .map(|h| self.get_fqdn(h))
                .collect();

            if *port == 443 {
                if let Ok(cert_names) = self.client.get_certificate_names(ip, *port) {
                    all_hostnames.extend(cert_names);
                }
            }

            let client = Arc::clone(&self.client);
            let baseline = Arc::new(baseline);
            let port = *port;
            let ip_clone = ip.to_string();
            let pb = self.progress.clone();

            let port_results: Vec<ScanResult> = stream::iter(all_hostnames)
                .map(move |hostname| {
                    let client = Arc::clone(&client);
                    let baseline = Arc::clone(&baseline);
                    let ip_closure = ip_clone.clone();
                    let pb = pb.clone();

                    async move {
                        let result = Scanner::scan_host_basic(
                            &client,
                            &ip_closure,
                            port,
                            &hostname,
                            &baseline,
                        ).await;

                        if let Some(pb) = &pb {
                            pb.inc(1);
                        }

                        result.ok()
                    }
                })
                .buffered(self.max_concurrent)
                .filter_map(|r| async move { r })
                .collect()
                .await;

            results.extend(port_results);
        }

        if !any_port_succeeded {
            results.push(ScanResult {
                hostname: format!("Failed to connect to {}", ip_ref),
                port: 0,
                status_code: 0,
                content_length: 0,
                server: None,
                similarity: 0.0,
                is_distinct: false,
                validation_method: "Connection Failed".to_string(),
            });
        }

        if let Some(pb) = &self.progress {
            pb.finish_and_clear();
        }

        results
    }

    pub async fn scan_advanced(&mut self, ip: &str, hostnames: Vec<String>) -> Vec<ScanResult> {
        let mut results = Vec::new();
        let mut any_port_succeeded = false;
        let ip_ref = ip.to_string();
    
        let total_ports = self.ports.len();
        let total_items = hostnames.len();
        let total_operations = total_ports * total_items;
    
        let pb = ProgressBar::new(total_operations as u64);
        pb.set_style(ProgressStyle::with_template(" {spinner:.cyan} [{bar:50.cyan/blue}] {pos}/{len} ({percent}%) [{elapsed_precise}] - {msg}")
            .unwrap()
            .progress_chars("█▓▒░")
            .tick_chars("⠋⠙⠚⠞⠖⠦⠴⠲⠳⠓"));
        pb.set_message(format!("IP: {}", ip));
        self.progress = Some(Arc::new(pb));

        for port in &self.ports {
            let baseline = match self.client.get_baseline(ip, *port).await {
                Ok(response) => response,
                Err(_) => {
                    if self.verbose {
                        eprintln!("[-] Failed to get baseline response from {}:{}", ip, port);
                    }
                    continue;
                }
            };

            any_port_succeeded = true;
            let patterns = Scanner::get_dynamic_patterns();
            let baseline_analysis = Scanner::analyze_content(&baseline.body, &patterns);
            let baseline_analysis = Arc::new(baseline_analysis);

            let mut all_hostnames: HashSet<String> = hostnames.iter()
                .map(|h| self.get_fqdn(h))
                .collect();
            
            if *port == 443 {
                if let Ok(cert_names) = self.client.get_certificate_names(ip, *port) {
                    all_hostnames.extend(cert_names);
                }
            }

            let client = Arc::clone(&self.client);
            let baseline = Arc::new(baseline);
            let content_hashes = self.content_hashes.clone();
            let section_hashes = self.section_hashes.clone();
            let pattern_frequencies = self.pattern_frequencies.clone();
            let baseline_analysis = baseline_analysis.clone();
            let port = *port;
            let ip_clone = ip.to_string();
            let pb = self.progress.clone();

            let advanced_results: Vec<AdvancedScanResult> = stream::iter(all_hostnames)
                .map(move |hostname| {
                    let client = Arc::clone(&client);
                    let baseline = Arc::clone(&baseline);
                    let content_hashes = content_hashes.clone();
                    let section_hashes = section_hashes.clone();
                    let pattern_frequencies = pattern_frequencies.clone();
                    let baseline_analysis = baseline_analysis.clone();
                    let patterns = patterns.clone();
                    let ip_closure = ip_clone.clone();
                    let pb = pb.clone();
                    
                    async move {
                        let result = Scanner::scan_host_advanced(
                            &client,
                            &ip_closure,
                            port,
                            &hostname,
                            &baseline,
                            &baseline_analysis,
                            &content_hashes,
                            &section_hashes,
                            &pattern_frequencies,
                            &patterns,
                        ).await;

                        if let Some(pb) = &pb {
                            pb.inc(1);
                        }

                        result.ok()
                    }
                })
                .buffered(self.max_concurrent)
                .filter_map(|r| async move { r })
                .collect()
                .await;

            let port_results: Vec<ScanResult> = advanced_results.into_iter()
                .map(|advanced| ScanResult {
                    hostname: advanced.hostname,
                    port,
                    status_code: advanced.status_code,
                    content_length: advanced.content_length,
                    server: advanced.server,
                    similarity: advanced.similarity,
                    is_distinct: advanced.is_distinct,
                    validation_method: advanced.validation_method,
                })
                .collect();

            results.extend(port_results);
        }

        if !any_port_succeeded {
            results.push(ScanResult {
                hostname: format!("Failed to connect to {}", ip_ref),
                port: 0,
                status_code: 0,
                content_length: 0,
                server: None,
                similarity: 0.0,
                is_distinct: false,
                validation_method: "Connection Failed".to_string(),
            });
        }

        if let Some(pb) = &self.progress {
            pb.finish_and_clear();
        }

        results
    }

    async fn scan_host_basic(
        client: &HttpClient,
        ip: &str,
        port: u16,
        hostname: &str,
        baseline: &VHostResponse,
    ) -> Result<ScanResult, Box<dyn std::error::Error>> {
        let response = client.check_virtual_host(ip, port, hostname).await?;
        let similarity = Scanner::calculate_similarity_static(&baseline.body, &response.body);
        let content_length_diff = (response.content_length as f64 - baseline.content_length as f64).abs() / baseline.content_length as f64;
        
        let is_valid_domain = client.validate_domain(hostname, ip, &[port]).await;
        let header_difference = Scanner::compare_headers_static(&baseline.headers, &response.headers);
        let status_difference = response.status != baseline.status;
        let server_difference = response.server != baseline.server;

        let is_distinct = similarity < SIMILARITY_THRESHOLD || 
                         content_length_diff > CONTENT_LENGTH_THRESHOLD ||
                         status_difference ||
                         server_difference ||
                         header_difference ||
                         is_valid_domain;

        let validation_method = if is_valid_domain {
            "DNS Resolution".to_string()
        } else if baseline.certificate_names.contains(hostname) {
            "SSL Certificate".to_string()
        } else if is_distinct {
            format!("Content Difference ({})", Scanner::get_difference_reason_static(
                similarity,
                content_length_diff,
                status_difference,
                server_difference,
                header_difference
            ))
        } else {
            "Not Validated".to_string()
        };

        Ok(ScanResult {
            hostname: hostname.to_string(),
            port,
            status_code: response.status,
            content_length: response.content_length,
            server: response.server,
            similarity,
            is_distinct,
            validation_method,
        })
    }

    async fn scan_host_advanced(
        client: &HttpClient,
        ip: &str,
        port: u16,
        hostname: &str,
        baseline: &VHostResponse,
        baseline_analysis: &ContentAnalysis,
        content_hashes: &tokio::sync::Mutex<HashMap<u64, usize>>,
        section_hashes: &tokio::sync::Mutex<HashMap<u64, usize>>,
        pattern_frequencies: &tokio::sync::Mutex<HashMap<String, usize>>,
        patterns: &[DynamicContentInfo],
    ) -> Result<AdvancedScanResult, Box<dyn std::error::Error>> {
        let response = client.check_virtual_host(ip, port, hostname).await?;
        let similarity = Scanner::calculate_similarity_static(&baseline.body, &response.body);
        let content_length_diff = (response.content_length as f64 - baseline.content_length as f64).abs() / baseline.content_length as f64;
        
        let is_valid_domain = client.validate_domain(hostname, ip, &[port]).await;
        let header_difference = Scanner::compare_headers_static(&baseline.headers, &response.headers);
        let status_difference = response.status != baseline.status;
        let server_difference = response.server != baseline.server;

        let analysis = Scanner::analyze_content(&response.body, patterns);
        
        let mut content_hashes = content_hashes.lock().await;
        *content_hashes.entry(analysis.full_hash).or_default() += 1;
        
        let mut section_hashes = section_hashes.lock().await;
        for section in &analysis.sections {
            *section_hashes.entry(section.hash).or_default() += 1;
        }

        let mut pattern_freqs = pattern_frequencies.lock().await;
        for pattern in &analysis.dynamic_patterns {
            *pattern_freqs.entry(pattern.pattern_type.clone()).or_default() += pattern.count;
        }
        
        let is_catchall = analysis.is_catchall || analysis.full_hash == baseline_analysis.full_hash;
        let dynamic_confidence = analysis.confidence;
        
        let detected_patterns: Vec<String> = analysis.dynamic_patterns
            .iter()
            .map(|p| p.pattern_type.clone())
            .collect();

        let is_distinct = similarity < SIMILARITY_THRESHOLD || 
                        content_length_diff > CONTENT_LENGTH_THRESHOLD ||
                        status_difference ||
                        server_difference ||
                        header_difference ||
                        is_valid_domain ||
                        !is_catchall;

        let validation_method = if is_valid_domain {
            "DNS Resolution".to_string()
        } else if baseline.certificate_names.contains(hostname) {
            "SSL Certificate".to_string()
        } else if is_catchall {
            if analysis.is_dynamic_catchall {
                format!("Dynamic Catch-all (Confidence: {:.2}%)", dynamic_confidence * 100.0)
            } else {
                "Static Catch-all".to_string()
            }
        } else if is_distinct {
            format!("Content Difference ({})", Scanner::get_difference_reason_static(
                similarity,
                content_length_diff,
                status_difference,
                server_difference,
                header_difference
            ))
        } else {
            "Not Validated".to_string()
        };

        Ok(AdvancedScanResult {
            hostname: hostname.to_string(),
            port,
            status_code: response.status,
            content_length: response.content_length,
            server: response.server,
            similarity,
            is_distinct,
            validation_method,
            is_catchall,
            is_dynamic_catchall: analysis.is_dynamic_catchall,
            dynamic_confidence,
            detected_patterns,
        })
    }

    fn get_difference_reason_static(
        similarity: f64,
        content_length_diff: f64,
        status_difference: bool,
        server_difference: bool,
        header_difference: bool
    ) -> String {
        let mut reasons = Vec::new();
        
        if similarity < SIMILARITY_THRESHOLD {
            reasons.push("Content");
        }
        if content_length_diff > CONTENT_LENGTH_THRESHOLD {
            reasons.push("Length");
        }
        if status_difference {
            reasons.push("Status");
        }
        if server_difference {
            reasons.push("Server");
        }
        if header_difference {
            reasons.push("Headers");
        }
        
        reasons.join(", ")
    }

    fn compare_headers_static(baseline: &HeaderMap, response: &HeaderMap) -> bool {
        let important_headers = ["server", "x-powered-by", "x-frame-options", "x-content-type-options"];
        
        for header in important_headers.iter() {
            if baseline.get(*header) != response.get(*header) {
                return true;
            }
        }
        false
    }

    fn calculate_similarity_static(text1: &str, text2: &str) -> f64 {
        let diff = TextDiff::from_lines(text1, text2);
        let mut same_count = 0;
        let mut total_count = 0;

        for change in diff.iter_all_changes() {
            match change.tag() {
                ChangeTag::Equal => same_count += 1,
                _ => (),
            }
            total_count += 1;
        }

        same_count as f64 / total_count as f64
    }

    fn get_dynamic_patterns() -> Vec<DynamicContentInfo> {
        vec![
            DynamicContentInfo {
                pattern_type: "Date".to_string(),
                pattern: Regex::new(r"\d{4}-\d{2}-\d{2}").unwrap(),
            },
            DynamicContentInfo {
                pattern_type: "Timestamp".to_string(),
                pattern: Regex::new(r"\d{2}:\d{2}:\d{2}").unwrap(),
            },
            DynamicContentInfo {
                pattern_type: "UUID".to_string(),
                pattern: Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap(),
            },
            DynamicContentInfo {
                pattern_type: "Random String".to_string(),
                pattern: Regex::new(r"[A-Za-z0-9]{32,}").unwrap(),
            },
            DynamicContentInfo {
                pattern_type: "Session ID".to_string(),
                pattern: Regex::new(r"sess(ion)?[-_]?[id]?=[\w-]+").unwrap(),
            },
            DynamicContentInfo {
                pattern_type: "Template Variable".to_string(),
                pattern: Regex::new(r"\{\{[\s\w\.-]+\}\}|\{%[\s\w\.-]+%\}").unwrap(),
            },
        ]
    }

    fn find_dom_sections(content: &str) -> Vec<(String, String)> {
        let section_patterns = [
            (r#"<header[^>]*>.*?</header>"#, "header"),
            (r#"<nav[^>]*>.*?</nav>"#, "navigation"),
            (r#"<main[^>]*>.*?</main>"#, "main"),
            (r#"<article[^>]*>.*?</article>"#, "article"),
            (r#"<section[^>]*>.*?</section>"#, "section"),
            (r#"<footer[^>]*>.*?</footer>"#, "footer"),
            (r#"<div[^>]*class=["'][\w\s-]*content[\w\s-]*["'][^>]*>.*?</div>"#, "content"),
            (r#"<div[^>]*class=["'][\w\s-]*container[\w\s-]*["'][^>]*>.*?</div>"#, "container"),
        ];

        let mut sections = Vec::new();
        for (pattern, section_type) in section_patterns.iter() {
            if let Ok(regex) = Regex::new(&format!("(?s){}", pattern)) {
                for cap in regex.captures_iter(content) {
                    let section_content = cap[0].to_string();
                    if section_content.len() >= MIN_SECTION_LENGTH {
                        sections.push((section_type.to_string(), section_content));
                    }
                }
            }
        }
        sections
    }

    fn analyze_content(content: &str, patterns: &[DynamicContentInfo]) -> ContentAnalysis {
        let full_hash = Scanner::calculate_hash(content);
        let dom_sections = Scanner::find_dom_sections(content);
        
        let mut all_patterns = Vec::new();
        for pattern_info in patterns.iter() {
            let matches: Vec<_> = pattern_info.pattern.find_iter(content).collect();
            if !matches.is_empty() {
                all_patterns.push(ContentPattern {
                    pattern_type: pattern_info.pattern_type.clone(),
                    count: matches.len(),
                });
            }
        }

        let sections: Vec<ContentSection> = dom_sections
            .into_iter()
            .map(|(section_type, content)| {
                let section_patterns: Vec<ContentPattern> = patterns
                    .iter()
                    .filter_map(|pattern_info| {
                        let matches: Vec<_> = pattern_info.pattern.find_iter(&content).collect();
                        if !matches.is_empty() {
                            Some(ContentPattern {
                                pattern_type: pattern_info.pattern_type.clone(),
                                count: matches.len(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect();

                let is_dynamic = section_patterns.iter()
                    .map(|p| p.count)
                    .sum::<usize>() as f64 / content.len() as f64 > DYNAMIC_PATTERN_THRESHOLD;

                ContentSection {
                    hash: Scanner::calculate_hash(&content),
                    content_type: section_type,
                    is_dynamic,
                }
            })
            .collect();

        let weighted_confidence: f64 = sections.iter()
            .map(|section| {
                let weight = SECTION_WEIGHTS.iter()
                    .find(|(_, stype)| *stype == section.content_type)
                    .map_or(1.0, |(w, _)| *w);
                if section.is_dynamic { weight } else { 0.0 }
            })
            .sum::<f64>();

        let total_weights: f64 = sections.iter()
            .map(|section| {
                SECTION_WEIGHTS.iter()
                    .find(|(_, stype)| *stype == section.content_type)
                    .map_or(1.0, |(w, _)| *w)
            })
            .sum();

        let confidence = if total_weights > 0.0 {
            weighted_confidence / total_weights
        } else {
            0.0
        };

        let is_dynamic_catchall = sections.iter().any(|s| s.is_dynamic);
        let is_catchall = !all_patterns.is_empty();

        ContentAnalysis {
            full_hash,
            sections,
            dynamic_patterns: all_patterns,
            is_catchall,
            is_dynamic_catchall,
            confidence,
        }
    }

    fn calculate_hash<T: Hash + ?Sized>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }
}