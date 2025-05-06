# vhsRekon
vhsRekon is a reconnaissance/research tool used for resolving domains or subdomains vHosts (for example nginx or Caddy) are listening for.\
Often this information is hidden behind wildcard domains, Cloudflare or other obstructive ways..\
This tool solves this issue for the research phase of penetration testing by resolving the domains/technologies to specific IPs and providing the information in an easy to use format.
<dl>
<h3><i>Who is this for?</i></h3>
    <dd>
        This tool is for anyone who wishes to use it. Whether you're a SysAdmin, Server Admin, Network admin or other IT employee.<br />
        Do note that the tool is created by and for, Cybersecurity professionals. It only gives information which might be relevant to those use cases.
    </dd>

<h3><i>Why?</i></h3>
    <dd>
        Most tools I've encountered has issues. Either, they're written in Python (which is great!) and the packages are too outdated to run. Or, they're multi-use tools which fail to properly validate - which causes a long work time with no results when scanning vHosts.<br />
        vhsRekon aims to solve both those issues. Written in Rust it's quick, lightweight and optimized. Making it work easily both as a standalone program and as a container.<br />
        For information on exactly what features vhsRekon has, check the features section.
    </dd>
</dl>

![vhsRekon in Progress](https://github.com/0xnoid/vhsRekon/blob/142f2c9260af31a10bc70f0d9f1696c3ab8e0109/vhsRekonScreenshotProg.png)

## Features
- [x] Automated Scanning
- [x] Wordlist Integration
- [x] Multiscan: Multiple IPs & Domains
- [x] Port Selection
- [x] Server Information
- [x] Results Report
- [x] Catch-All Scenarios
- [x] Dynamic Catch-All Scenarios
- [x] HTTP Code Filter
- [x] Header Validation
- [x] Response Validation
- [x] DNS Resolution Validation
- [x] SSL/Certificate Validation

### Roadmap
- [x] Port Selection
- [x] Detect Catch-All
- [x] Dynamic Catch-All
- [x] vHost Report: Server Info
- [ ] Alias Discovery
- [ ] Fuzzer
- [ ] Redirects
- [ ] Integrate Other Tools



## Usage

```sh
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


Scan virtual hosts

Usage: vhsrekon [OPTIONS] --ip <IP>

Options:
  -i, --ip <IP>                          Target IP or file (one per line)
  -d, --domain <DOMAIN>                  Target domain or file (e.g. foo.com)
  -p, --ports <PORTS>...                 Ports to scan (e.g. -p 80 443)
  -w, --wordlist <WORDLIST>              Wordlist [integrated: 'services', 'namelist', 'top500']
  -v, --verbose                          Enable verbose output
  -o, --output <OUTPUT>                  Save output to a file
  -z, --verbose-output <VERBOSE_OUTPUT>  Save verbose output to a file
  -f, --show-failed                      Show failed attempts
  -c, --concurrent <CONCURRENT>          Max concurrent requests (Default: 100)
  -q                                     Detailed output (verification type, etc.)
  -s, --scenario-catch                   Enable dynamic catch-all detection
  -h, --help                             Print help (see more with '--help')
  -V, --version                          Print version

```

Examples:

```sh
vhsrekon -i 127.0.0.1 -d foo.com
```

```sh
vhsrekon -i 127.0.0.1 -d foo.com -w wordlist.txt -o result.txt
```

```sh
vhsrekon -i ips.txt -d domains.txt -o results.txt
```

### Argument Info
***Wordlists*** `-w {arg}` / `--wordlist {arg}`<br />
Use: Not required. Defaults to the wordlist `services`.\
We recommend creating your own wordlist using [OWASP Amass](https://github.com/owasp-amass/amass) to ease the process.\
However, there are 3 wordlists included: Services ([SecLists](https://github.com/danielmiessler/SecLists)), Namelist ([SecLists](https://github.com/danielmiessler/SecLists)) and Top 500 ([dnsscan](https://github.com/rbsec/dnscan)).
<br /><br />
To use the integrated wordlists we can use the arguments `services`, `namelist` or `top500`. Example: `-w top500`<br>
To use a custom wordlist, make your wordlist in `.txt` with 1 subdomain per line. We may then use the argument `wordlist.txt`. Example: `-w mywordlist.txt`
<br /><br />
***Output*** `-o {arg}` / `--output {arg}`<br />
This command generates a report containing what vHosts were found, including how it was validated. Example: `-o result.txt`
<br /><br />
***Verbose*** `-v` / `--verbose`<br />
***Verbose: File*** `-z`/ `--verbose-output {arg}`<br />
We may use either or both at the same time. They are not mutually inclusive/exclusive.\
Example (Terminal Output): `-v`<br />
Example (File Output): `-z verbose.txt`<br />
Example (Both): `-v -z verbose.txt`
<br /><br />
***Show failed*** `-f` / `--show-failed`<br />
Includes failed attempts in result. Useful for small wordlists, but refrain from using with bigger ones.
<br /><br />
***Concurrent*** `-c {arg}` / `--concurrent {arg}`<br />
Sets the maximum concurrent connections to the target.\
The default is set to `100`. We do not recommend going above `150` as you may be struck with rate limiting and/or IP ban.
<br /><br />
***Catch-All Scenarios*** `-s` / `--scenario-catch`
Hashes results and analyzes part of page contents, comparing them automatically. This is usually not needed and will increase scan time.\
Default mode is to run without this function.

## Installation
There are multiple options, but I recommend installing the tool directly for ease of use which will allow better organization of input/output files.\
The easiest way to achieve this is to install the premade packages:
```sh
curl -sSL https://raw.githubusercontent.com/0xnoid/vhsrekon/main/install.sh | sudo bash
```
<sup><sup>The script currently supports the following package managers: `deb`, `rpm` and `pacman`.</sup></sup>


### Docker
If you prefer using Docker, you'll need to compile it.

<details><summary>Quick Script</summary>
You may use the quick script:

```sh
curl -sSL https://raw.githubusercontent.com/0xnoid/vhsrekon/main/install-docker.sh | bash
```
</details>

<details><summary>Manually</summary>
Or, if you prefer to do it manually:

```sh
git clone https://github.com/0xnoid/vhsrekon
cd vhsrekon
docker build -t vhsrekon .
```
</details>

Once built, simply run it:

```sh
docker run -it --rm vhsrekon --help
```

Then after that we may reuse the container whenever:

```sh
docker run -it vhsrekon {arg}
```

### Build it yourself
<details>
To build it yourself, there are a few requirements.\
First, you'll need Rust

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
Next, you'll need build tools


<details><summary>Debian Based</summary>

```sh
sudo apt install build-essential
```

</details>

<details><summary>Arch Based</summary>

```sh
sudo pacman -S base-devel
```

</details>

<details><summary>Fedora Based</summary>

```sh
sudo dnf install make automake gcc gcc-c++ kernel-devel  
```

OR:

```sh
sudo dnf install @development-tools
```

OR:
```sh
dnf group install "Development Tools"
```

The first one will install the least amount of required tools.
</details>

After that, clone this and build it

```sh
git clone https://github.com/0xnoid/vhsrekon
cd vhsrekon
cargo build --release
```

You may then either move it, or use it from the folder.\
We suggest moving it to your `/usr/bin/`.

```sh
./target/release/vhsrekon -h
```

</details>


## Preparation
vhsRekon may be used as a standalone program, but there are some suggestions on how to improve your scans.\
This includes using other tools to create Wordlists and IP lists, which will drastically improve both your success rate and scan time - especially for multi-target use.

***Why***?\
By preparing we can avoid hitting the Target when we don't need to. This will allow our requests to look more legitimate and avoid detection.

***What should I prepare***?\
You'll want to prepare both a Wordlist and an IP list, the tools below will help generate both of these items.

<dl>
<h3><i>Wordlist</i></h3>
    <dd>
        Creating a Wordlist of subdomains will aid us in finding the subdomains which may not be listed in public sources.<br />
        This often includes wildcard domains and other items which the Target's domain/range might be listning for.<br />
        Useful tools for this portion of Discovery:
        <dl>
            <dt><a href="https://github.com/owasp-amass/amass">OWASP Amass</a></dt>
                <dd>
                    <b><i>Enumeration tool.</i></b> This tool can scan both passively and actively scan, it's one of the most full fletched tools you can use for finding any subdomain with bruteforce, wordlists, etc.<br />
                    Highly recommended for creating your wordlist. Built in with most pentest OSes.
                </dd>
            <dt><a href="https://github.com/SparrowOchon/dnsenum2">dnsenum</a></dt>
                <dd>
                    <b><i>Enumeration tool.</i></b> This tool is easy to use and has multiple options, such as brute force, Google scraping and passive enumeration (DNS).<br />
                    Highly recommended for creating your wordlist with the XML output, but needs to be converted before use. Built in with most pentest OSes.
                </dd>
        </dl>
    </dd>
<h3><i>IP Discovery</i></h3>
    <dd>
        Finding the target IPs can often be easy, there are of course multiple ways to do this. If the target is simple, we may of course use tools such as whois, traceroute and DNS querying.<br />
        However, since most hosts nowadays use CloudFlare to obfuscate the IP we might also need to dig deeper for the source IP.<br />
        Useful tools:
        <dl>
            <dt><a href="https://github.com/0xnoid/CloudFail">CloudFail</a></dt>
                <dd>
                    <b><i>Find IPs and Subdomains.</i></b> Easy to use tool that scans CloudFlare leaked IPs, compares the domains and subdomains listed towards misconfigurations and previously leaked IPs by using multiple datasets and databases.<br />
                    Highly recommended for any target behind Cloudflare. Easy to use tool that can generate both IP list and Subdomain list.
                </dd>
            <dt><a href="https://github.com/rfc1036/whois">whois</a></dt>
                <dd>
                    <b><i>Whois terminal client.</i></b> Tool by Marco d'Itri that comes built in with most GNU/Linux distributions. Easy to use, but usually won't return all the data you need.<br />
                    Will not work if Cloudflare is enabled. Will only return domain you search.
                </dd>
            <dt><a href="https://linux.die.net/man/1/dig">Dig</a></dt>
                <dd>
                    <b><i>Query DNS name servers.</i></b> Tool by ISC that comes built in with GNU/Linux. Easy to use.<br />
                    Will not work if Cloudflare is enabled. Will only return domain you search.
                </dd>
            <dt><a href="https://github.com/SparrowOchon/dnsenum2">dnsenum</a></dt>
                <dd>
                    <b><i>Enumeration tool.</i></b> This tool is mentioned in the Wordlist, but it also returns IPs listed in the DNS.<br />
                    Will not work if Cloudflare is enabled. Will only return domain you search.
                </dd>
        </dl>
<h4>Scripts</h4>
    <dd>
        While most of these tools are useful, actually combining the data into a wordlist/ip list can be tedious.
        <dl>
            <dt><a href="https://github.com/0xnoid/kit/blob/master/report/amass.sh">Amass Report Generator</a></dt>
                <dd>
                    Wrapper bash script for OWASP Amass to generate HTML reports, subdomain wordlist and IP list.
                </dd>
        </dl>
</dl>


## Other
Commercial Requirements? Require a license for your operations? <a href="mailto:tools@mimmikk.com">Reach out</a>
