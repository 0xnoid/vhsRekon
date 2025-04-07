use clap::Parser;
use std::fs::{File, OpenOptions};
use std::io::{Write, BufRead, BufReader};
use std::time::{Instant, Duration};
use std::sync::Arc;
use std::sync::Mutex;
use std::path::Path;
use std::collections::{HashMap, HashSet};
use crate::lib::core::scan::{Scanner, ScanResult};
use crate::lib::util;
use indicatif::{ProgressBar, ProgressStyle};

const BANNER: &str = r#"
                        █▓           
                     ▒█▓▓▓█▓         
                   ▒██▓▓█████        
                 ░██▓▓████▓████      
               ▒█▓▓▓████▓░░▒████     
             ░█▓▓▓█████▓▓▒▒▒░ ▓▒▒█   
           ░██▓▓█████    ▓░░░░ ▒▒██  
         ░██▓▓█████        ▓░░░▒█████
       ▒██▓██████ ▒  ▒░▒    ▓▓█████▒ 
     ▒█▓▓██████▓ ▓  ▓ ░▒░ ▒ ▓█████   
   ▒██▓▓█████▓ ▓ ▒     ▒   █████     
 ▒███▒█████▓██▓ ▒░   ░   █████▒      
 ███▓████▓▓▒▒▓▒▓▓      ██████        
  ▒██████░▒▒▒▒ ░░▓▓  ▓█████          
    ▒▒▒█▓▒░▒ ░░ ▒▒░▓█████▒           
      ▒▒▒█▓░░░░ ░░██████             
        ▒▒█▓░░▒░██████               
         ░▒▒▓███████▒ vhsRekon       
           ▒▒▒█████ @0xnoid          
             ▒▒▒█ https://github.com/0xnoid                      
"#;

#[derive(Parser, Debug)]
#[command(author, version, about = "Scan virtual hosts", before_help = BANNER)]
#[command(long_about = "Scan virtual hosts (web servers) for accepted server names and listens")]
pub struct Cli {
   #[arg(short, long, help = "Target IP or file (one per line)")]
   ip: String,

   #[arg(short = 'd', long, help = "Target domain or file (e.g. foo.com)")]
   domain: Option<String>,

   #[arg(short, long, num_args = 1.., value_delimiter = ' ', help = "Ports to scan (e.g. -p 80 443)")]
   ports: Option<Vec<String>>,

   #[arg(short, long, help = "Wordlist [integrated: 'services', 'namelist', 'top500']")]
   wordlist: Option<String>,

   #[arg(short, long, help = "Enable verbose output")]
   verbose: bool,

   #[arg(short, long, help = "Save output to a file")]
   output: Option<String>,

   #[arg(short = 'z', long = "verbose-output", help = "Save verbose output to a file")]
   verbose_output: Option<String>,

   #[arg(short = 'f', long, help = "Show failed attempts")]
   show_failed: bool,

   #[arg(short = 'c', long, help = "Max concurrent requests (Default: 100)")]
   concurrent: Option<usize>,

   #[arg(short = 'q', help = "Detailed output (verification type, etc.)")]
   quiet: bool,

   #[arg(short = 's', long = "scenario-catch", help = "Enable dynamic catch-all detection")]
   scenario_catch: bool,
}

impl Cli {
    pub fn new() -> Self {
        Self::parse()
    }

    fn read_lines<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<String>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines()
            .filter_map(|line| line.ok())
            .filter(|line| !line.trim().is_empty())
            .collect();
        Ok(lines)
    }

    fn parse_ports(&self) -> Vec<u16> {
        if let Some(port_inputs) = &self.ports {
            if port_inputs.len() == 1 && Path::new(&port_inputs[0]).exists() {
                if let Ok(lines) = Self::read_lines(&port_inputs[0]) {
                    return lines.iter()
                        .filter_map(|line| line.parse::<u16>().ok())
                        .collect();
                }
            }
            port_inputs.iter()
                .filter_map(|p| p.parse::<u16>().ok())
                .collect()
        } else {
            vec![80, 443]
        }
    }

    fn parse_ips(&self) -> Vec<String> {
        if Path::new(&self.ip).exists() {
            Self::read_lines(&self.ip).unwrap_or_else(|_| vec![self.ip.clone()])
        } else {
            vec![self.ip.clone()]
        }
    }

    fn parse_domains(&self) -> Option<Vec<String>> {
        self.domain.as_ref().map(|domain| {
            if Path::new(domain).exists() {
                Self::read_lines(domain).unwrap_or_else(|_| vec![domain.clone()])
            } else {
                vec![domain.clone()]
            }
        })
    }

    fn write_to_file(file: &Arc<Mutex<File>>, msg: &str) -> std::io::Result<()> {
        if let Ok(mut file) = file.lock() {
            writeln!(file, "{}", msg)?;
        }
        Ok(())
    }

    fn get_wordlist_name(&self, path: &str) -> String {
        match path {
            "default" => "Default".to_string(),
            "namelist" => "Namelist".to_string(),
            "top500" => "Top 500".to_string(),
            "subdomains" => "Subdomains".to_string(),
            custom => custom.to_string(),
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let verbose_file = if let Some(ref path) = self.verbose_output {
            let file = File::create(path)?;
            writeln!(&file, "{}", BANNER)?;
            Some(Arc::new(Mutex::new(file)))
        } else {
            None
        };
    
        let verbose_callback = verbose_file.clone().map(|file| {
            move |msg: &str| {
                let file_clone = file.clone();
                let msg = msg.to_string();
                tokio::spawn(async move {
                    let _ = Self::write_to_file(&file_clone, &msg);
                });
            }
        });
    
        let wordlist_path = self.wordlist.as_deref().unwrap_or("default");
        let wordlist_name = self.get_wordlist_name(wordlist_path);
        let hostnames = util::read_wordlist(wordlist_path)?;
        let total_items = hostnames.len();
    
        let ips = self.parse_ips();
        let domains = self.parse_domains();
        let ports = self.parse_ports();
    
        println!("{}", BANNER);
        println!("\n [!] Target(s): {}", ips.join(", "));
        
        if let Some(ref domains) = domains {
            println!(" [!] Domain(s): {}", domains.join(", "));
        }
        
        println!(" [!] Port(s): {:?}", ports);
        println!(" [!] Wordlist: {} ({})", wordlist_name, total_items);
        
        if self.scenario_catch {
            println!(" [!] Mode: Catch-All Detection");
        } else {
            println!(" [!] Mode: Normal");
        }
    
        if let Some(ref path) = self.output {
            println!(" [!] Output: {}", path);
        }
        if let Some(ref path) = self.verbose_output {
            println!(" [!] Verbose Output: {}", path);
        }
        if let Some(concurrent) = self.concurrent {
            println!(" [!] Concurrent Requests: {}", concurrent);
        }
    
        let start_time = Instant::now();
        let mut ip_results = std::collections::HashMap::new();
        let mut total_valid_results = 0;
        let mut total_duplicates = 0;
    
        for ip in &ips {
            let mut ip_specific_results = Vec::new();
            let pb = ProgressBar::new((total_items * domains.as_ref().map_or(1, |d| d.len())) as u64);
            pb.set_style(ProgressStyle::with_template(" {spinner:.cyan} [{bar:50.cyan/blue}] {pos}/{len} ({percent}%) [{elapsed_precise}]")
                .unwrap()
                .progress_chars("█▓▒░")
                .tick_chars("⠋⠙⠚⠞⠖⠦⠴⠲⠳⠓"));
        
            if let Some(ref domains) = domains {
                for domain in domains {
                    let mut scanner = Scanner::new();
                    scanner.set_ports(ports.clone());
                    if let Some(concurrent) = self.concurrent {
                        scanner.set_max_concurrent(concurrent);
                    }
                    scanner.set_verbose(self.verbose || self.verbose_output.is_some());
                    if let Some(callback) = verbose_callback.clone() {
                        scanner.set_verbose_callback(callback.clone());
                    }
                    scanner.set_domain(domain.clone());
                    
                    let results = if self.scenario_catch {
                        scanner.scan_advanced(ip, hostnames.clone()).await
                    } else {
                        scanner.scan_basic(ip, hostnames.clone()).await
                    };
                    ip_specific_results.extend(results);
                }
            } else {
                let mut scanner = Scanner::new();
                scanner.set_ports(ports.clone());
                if let Some(concurrent) = self.concurrent {
                    scanner.set_max_concurrent(concurrent);
                }
                scanner.set_verbose(self.verbose || self.verbose_output.is_some());
                if let Some(callback) = verbose_callback.clone() {
                    scanner.set_verbose_callback(callback.clone());
                }
                
                let results = if self.scenario_catch {
                    scanner.scan_advanced(ip, hostnames.clone()).await
                } else {
                    scanner.scan_basic(ip, hostnames.clone()).await
                };
                ip_specific_results.extend(results);
            }
        
            pb.finish_and_clear();
    
            let valid_results: Vec<&ScanResult> = ip_specific_results.iter()
                .filter(|r| r.is_distinct)
                .collect();
    
            let mut seen_hostnames = std::collections::HashSet::new();
            let unique_count = valid_results.iter()
                .filter(|r| seen_hostnames.insert(&r.hostname))
                .count();
            let duplicate_count = valid_results.len() - unique_count;
    
            total_valid_results += unique_count;
            total_duplicates += duplicate_count;
    
            ip_results.insert(ip.clone(), ip_specific_results);
        }
    
        let elapsed = start_time.elapsed();
        println!("\n [=] Finished:");
        println!(" [=] Found {} results{} in total",
            total_valid_results,
            if total_duplicates > 0 { format!(" ({} duplicates)", total_duplicates) } else { String::new() }
        );
    
        for (ip, results) in &ip_results {
            let valid_results: Vec<&ScanResult> = results.iter()
                .filter(|r| r.is_distinct)
                .collect();
    
            let mut seen_hostnames = std::collections::HashSet::new();
            let unique_count = valid_results.iter()
                .filter(|r| seen_hostnames.insert(&r.hostname))
                .count();
            let duplicate_count = valid_results.len() - unique_count;
            
            println!(" [!] Found {} results{} for {}:",
                unique_count,
                if duplicate_count > 0 { format!(" ({} duplicates)", duplicate_count) } else { String::new() },
                ip
            );
    
            if !valid_results.is_empty() {
                let mut grouped_results: HashMap<String, Vec<&ScanResult>> = HashMap::new();
                
                for result in &valid_results {
                    grouped_results.entry(result.hostname.clone())
                        .or_default()
                        .push(result);
                }
            
                let mut sorted_hosts: Vec<_> = grouped_results.keys().cloned().collect();
                sorted_hosts.sort();
            
                if self.quiet {
                    for hostname in sorted_hosts {
                        let results = &grouped_results[&hostname];
                        let ports: Vec<String> = results.iter()
                            .map(|r| r.port.to_string())
                            .collect();
                        let output = format!("  Host: {}\n  ├── Port(s): {}\n  ├── Status: {}\n  ├── Length: {}\n  ├── Server: {}\n  ├── Similarity: {:.2}%\n  ├── Validation: {}\n  └── Distinct: {}\n",
                            hostname,
                            ports.join(", "),
                            results[0].status_code,
                            results[0].content_length,
                            results[0].server.as_ref().unwrap_or(&"Unknown".to_string()),
                            results[0].similarity * 100.0,
                            results[0].validation_method,
                            results[0].is_distinct
                        );
                        println!("{}", output);
                    }
                } else {
                    for hostname in sorted_hosts {
                        let results = &grouped_results[&hostname];
                        let ports: Vec<String> = results.iter()
                            .map(|r| r.port.to_string())
                            .collect();
                        println!(" [+] Validation: {} | Port(s): {} | Server: {} | Distinct: {} | Host(s): {}", 
                            results[0].validation_method,
                            ports.join(" "),
                            results[0].server.as_ref().unwrap_or(&"Unknown".to_string()),
                            results[0].is_distinct,
                            hostname
                        );
                    }
                }
            }
        }
    
        println!("\n [*] Time Elapsed: {:.2?}", elapsed);
    
        if let Some(path) = &self.output {
            self.save_results(&ip_results, path, false, &wordlist_name, total_items, elapsed, self.scenario_catch)?;
        }
    
        if let Some(path) = &self.verbose_output {
            self.save_results(&ip_results, path, true, &wordlist_name, total_items, elapsed, self.scenario_catch)?;
        }
    
        Ok(())
    }
    
    fn save_results(
        &self,
        ip_results: &HashMap<String, Vec<ScanResult>>,
        path: &str,
        verbose: bool,
        wordlist: &str,
        total_items: usize,
        elapsed: Duration,
        advanced_mode: bool
    ) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
    
        writeln!(file, "Scan Results:")?;
        writeln!(file, "Wordlist: {}", wordlist)?;
        writeln!(file, "Items Tried: {}", total_items)?;
    
        let ips = self.parse_ips();
        writeln!(file, "IP(s): {}", ips.join(", "))?;
    
        if let Some(ref _domain) = self.domain {
            if let Some(domains) = self.parse_domains() {
                writeln!(file, "Domain(s): {}", domains.join(", "))?;
            }
        }
    
        if let Some(ref ports) = self.ports {
            let ports_display = if ports.len() == 1 && Path::new(&ports[0]).exists() {
                format!("({}) {}", ports[0], Self::read_lines(&ports[0])?.join(", "))
            } else {
                ports.join(", ")
            };
            writeln!(file, "Port(s): {}", ports_display)?;
        }
        
        writeln!(file, "Mode: {}", if advanced_mode { "Catch-All Detection" } else { "Normal" })?;
        writeln!(file, "Total Time Elapsed: {:.2?}", elapsed)?;
    
        let mut total_valid_results = 0;
        let mut total_duplicates = 0;
    
        for results in ip_results.values() {
            let valid_results: Vec<&ScanResult> = results.iter()
                .filter(|r| r.is_distinct)
                .collect();
    
            let mut seen_hostnames = HashSet::new();
            let unique_count = valid_results.iter()
                .filter(|r| seen_hostnames.insert(&r.hostname))
                .count();
            let duplicate_count = valid_results.len() - unique_count;
    
            total_valid_results += unique_count;
            total_duplicates += duplicate_count;
        }
    
        writeln!(file, "Results: Found {} ({})", 
            total_valid_results,
            if total_duplicates > 0 { format!("{} duplicates", total_duplicates) } else { String::new() }
        )?;
    
        for (ip, results) in ip_results {
            let valid_results: Vec<&ScanResult> = results.iter()
                .filter(|r| r.is_distinct)
                .collect();
    
            let mut seen_hostnames = HashSet::new();
            let unique_count = valid_results.iter()
                .filter(|r| seen_hostnames.insert(&r.hostname))
                .count();
            let duplicate_count = valid_results.len() - unique_count;
    
            writeln!(file, "\nFound {} results{} for IP {}:",
                unique_count,
                if duplicate_count > 0 { format!(" ({} duplicates)", duplicate_count) } else { String::new() },
                ip
            )?;
            
            seen_hostnames.clear();
            let mut sorted_hostnames: Vec<_> = valid_results.iter()
                .filter(|r| seen_hostnames.insert(&r.hostname))
                .map(|r| &r.hostname)
                .collect();
            sorted_hostnames.sort();
            
            for hostname in &sorted_hostnames {
                writeln!(file, "{}", hostname)?;
            }
        }
    
        writeln!(file, "\n----------------------------------------")?;
        writeln!(file, "Resolve Details:\n")?;
    
        let mut all_grouped: HashMap<String, Vec<(&str, &ScanResult)>> = HashMap::new();
        for (ip, results) in ip_results {
            for result in results {
                if !result.is_distinct && !verbose && !self.show_failed {
                    continue;
                }
                all_grouped.entry(result.hostname.clone())
                    .or_default()
                    .push((ip, result));
            }
        }
    
        let mut sorted_hosts: Vec<_> = all_grouped.keys().collect();
        sorted_hosts.sort();
    
        for hostname in sorted_hosts {
            let results = &all_grouped[hostname];
            let (_, first_result) = &results[0];
            
            let unique_ips: HashSet<&str> = results.iter()
                .map(|(ip, _)| *ip)
                .collect();

            let unique_ports: HashSet<u16> = results.iter()
                .map(|(_, result)| result.port)
                .collect();

            let mut sorted_ips: Vec<_> = unique_ips.into_iter().collect();
            sorted_ips.sort();

            let mut sorted_ports: Vec<_> = unique_ports.into_iter().collect();
            sorted_ports.sort_unstable();
    
            writeln!(file, "Host(s): {}", hostname)?;
            writeln!(file, "IP(s): {}", sorted_ips.join(", "))?;
            writeln!(file, "Port(s): {}", sorted_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "))?;
            writeln!(file, "Status: {}", first_result.status_code)?;
            writeln!(file, "Length: {}", first_result.content_length)?;
            writeln!(file, "Server: {}", first_result.server.as_ref().unwrap_or(&"Unknown".to_string()))?;
            writeln!(file, "Similarity: {:.2}%", first_result.similarity * 100.0)?;
            writeln!(file, "Validation: {}", first_result.validation_method)?;
            writeln!(file, "Distinct: {}", first_result.is_distinct)?;
            writeln!(file)?;
        }
        
        Ok(())
    }
}