use std::fs::File;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

const DEFAULT_WORDLIST: &str = include_str!("lists/services.txt");
const LISTS_DIR: &str = "src/lib/lists";

pub fn get_wordlist_path(wordlist: &str) -> PathBuf {
    match wordlist {
        "namelist" => PathBuf::from(LISTS_DIR).join("namelist.txt"),
        "subdomains" => PathBuf::from(LISTS_DIR).join("subdomains.txt"),
        "top500" => PathBuf::from(LISTS_DIR).join("top500.txt"),
        path => PathBuf::from(path)
    }
}

pub fn read_wordlist<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    if !path.as_ref().exists() {
        let path_with_ext = path.as_ref().with_extension("txt");
        if path_with_ext.exists() {
            return read_file(&path_with_ext);
        }
        return Ok(DEFAULT_WORDLIST
            .lines()
            .map(String::from)
            .collect());
    }
    read_file(path)
}

fn read_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    Ok(reader.lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .collect())
}