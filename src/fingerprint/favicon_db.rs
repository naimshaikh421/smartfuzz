//! Free embedded favicon hash database (MMH3).
//! Hashes from public OSINT/recon communities — no paid API, fully offline.

use murmur3::murmur3_32;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::OnceLock;

static MMH3_DB: &[(&str, i32)] = &[
    ("WordPress", -335242539),
    ("WordPress", -1059710216),
    ("Joomla", 1620285968),
    ("Joomla", 366524387),
    ("Drupal", 1174841451),
    ("Drupal", -167656799),
    ("Jenkins", 81586312),
    ("Jenkins", 1937206818),
    ("GitLab", 1278323681),
    ("GitLab", 516963061),
    ("Atlassian Jira", 981867722),
    ("Atlassian Confluence", 305412615),
    ("Spring Boot", 116323821),
    ("Tomcat", -297069493),
    ("Apache", -1437701105),
    ("Nginx", 979851577),
    ("IIS", 442749392),
    ("Microsoft SharePoint", -1452846740),
    ("phpMyAdmin", -1010568380),
    ("Grafana", -1654229045),
    ("Kibana", -267431135),
    ("Elastic", -1200737715),
    ("Swagger UI", 1640159957),
    ("Rocket.Chat", 225632504),
    ("OpenStack", 786533217),
    ("Zabbix", 892542951),
    ("Cisco", -1807411396),
    ("Fortinet", 945408572),
    ("Palo Alto", 602431586),
    ("Citrix", -1166125410),
    ("Weblogic", 705143395),
    ("Roundcube", 119741608),
    ("OwnCloud", -1642532491),
    ("Nextcloud", -1255347784),
    ("Magento", -38580010),
    ("Shopify", 1280907310),
    ("Ghost", -1015932800),
    ("Discourse", -178685903),
    ("Moodle", -438482901),
];

fn mmh3_map() -> &'static HashMap<i32, Vec<&'static str>> {
    static MAP: OnceLock<HashMap<i32, Vec<&'static str>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m: HashMap<i32, Vec<&'static str>> = HashMap::new();
        for (name, hash) in MMH3_DB {
            m.entry(*hash).or_default().push(*name);
        }
        m
    })
}

/// MMH3 hash of raw favicon bytes (httpx/Shodan compatible).
pub fn favicon_mmh3(body: &[u8]) -> i32 {
    let mut cursor = Cursor::new(body);
    murmur3_32(&mut cursor, 0).unwrap_or(0) as i32
}

pub fn lookup_mmh3(hash: i32) -> Vec<&'static str> {
    mmh3_map().get(&hash).cloned().unwrap_or_default()
}

pub fn identify_favicon(body: &[u8]) -> Vec<String> {
    let mmh3 = favicon_mmh3(body);
    let mut out: Vec<String> = lookup_mmh3(mmh3)
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmh3_deterministic() {
        assert_eq!(favicon_mmh3(b"test"), favicon_mmh3(b"test"));
    }

    #[test]
    fn wordpress_hash_known() {
        assert!(lookup_mmh3(-335242539)
            .iter()
            .any(|n| n.contains("WordPress")));
    }
}
