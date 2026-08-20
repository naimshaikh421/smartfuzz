//! Free wordlist catalog — SecLists (GitHub) + local paths. No paid services.

use crate::cli::ScanMode;

pub const SECLISTS_RAW_BASE: &str =
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content";

const ALL: [ScanMode; 3] = [ScanMode::Fast, ScanMode::Balanced, ScanMode::Deep];
const BALANCED_DEEP: [ScanMode; 2] = [ScanMode::Balanced, ScanMode::Deep];

/// One wordlist entry in the catalog.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub id: &'static str,
    pub name: &'static str,
    pub seclists_path: &'static str,
    pub priority: u8,
    pub tech_tags: &'static [&'static str],
    pub modes: &'static [ScanMode],
}

pub const UNIVERSAL: &[CatalogEntry] = &[
    CatalogEntry {
        id: "quickhits",
        name: "SecLists quickhits",
        seclists_path: "quickhits.txt",
        priority: 62,
        tech_tags: &[],
        modes: &[ScanMode::Fast],
    },
    CatalogEntry {
        id: "common",
        name: "SecLists common",
        seclists_path: "common.txt",
        priority: 58,
        tech_tags: &[],
        modes: &ALL,
    },
    CatalogEntry {
        id: "big",
        name: "SecLists big",
        seclists_path: "big.txt",
        priority: 52,
        tech_tags: &[],
        modes: &[ScanMode::Deep],
    },
    CatalogEntry {
        id: "api-endpoints",
        name: "API endpoints",
        seclists_path: "api/api-endpoints.txt",
        priority: 82,
        tech_tags: &[
            "api", "graphql", "swagger", "openapi", "rest", "spring", "express", "node",
        ],
        modes: &BALANCED_DEEP,
    },
];

pub const TECH: &[CatalogEntry] = &[
    CatalogEntry {
        id: "wordpress",
        name: "WordPress fuzz",
        seclists_path: "CMS/wordpress.fuzz.txt",
        priority: 92,
        tech_tags: &["wordpress"],
        modes: &ALL,
    },
    CatalogEntry {
        id: "drupal",
        name: "Drupal",
        seclists_path: "CMS/Drupal.txt",
        priority: 92,
        tech_tags: &["drupal"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "joomla",
        name: "Joomla",
        seclists_path: "CMS/trickest-cms-wordlist/joomla.txt",
        priority: 92,
        tech_tags: &["joomla"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "django",
        name: "Django",
        seclists_path: "CMS/Django.txt",
        priority: 91,
        tech_tags: &["django"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "php",
        name: "PHP paths",
        seclists_path: "Programming-Language-Specific/PHP.fuzz.txt",
        priority: 90,
        tech_tags: &["php", "laravel"],
        modes: &ALL,
    },
    CatalogEntry {
        id: "apache",
        name: "Apache",
        seclists_path: "Web-Servers/Apache.txt",
        priority: 88,
        tech_tags: &["apache"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "nginx",
        name: "Nginx",
        seclists_path: "Web-Servers/nginx.txt",
        priority: 88,
        tech_tags: &["nginx"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "iis",
        name: "Microsoft IIS",
        seclists_path: "Web-Servers/IIS.txt",
        priority: 90,
        tech_tags: &["iis", "asp.net"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "tomcat",
        name: "Apache Tomcat",
        seclists_path: "Web-Servers/Apache-Tomcat.txt",
        priority: 90,
        tech_tags: &["tomcat"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "spring",
        name: "Java Spring Boot",
        seclists_path: "Programming-Language-Specific/Java-Spring-Boot.txt",
        priority: 91,
        tech_tags: &["spring"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "java-servlets",
        name: "Java servlets",
        seclists_path: "JavaServlets-Common.fuzz.txt",
        priority: 88,
        tech_tags: &["java", "spring", "servlet"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "nodejs",
        name: "JavaScript / Node",
        seclists_path: "JavaScript-Miners.txt",
        priority: 88,
        tech_tags: &["node", "express", "next"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "rails",
        name: "Ruby on Rails",
        seclists_path: "Programming-Language-Specific/ror.txt",
        priority: 90,
        tech_tags: &["rails", "ruby"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "graphql",
        name: "GraphQL",
        seclists_path: "graphql.txt",
        priority: 85,
        tech_tags: &["graphql"],
        modes: &BALANCED_DEEP,
    },
    CatalogEntry {
        id: "backups",
        name: "Common DB backups",
        seclists_path: "Common-DB-Backups.txt",
        priority: 86,
        tech_tags: &[],
        modes: &[ScanMode::Deep],
    },
];

pub fn seclists_url(relative_path: &str) -> String {
    format!("{SECLISTS_RAW_BASE}/{relative_path}")
}
