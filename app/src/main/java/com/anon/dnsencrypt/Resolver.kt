package com.anon.dnsencrypt

enum class Resolver(val label: String, val dohUrl: String) {
    ADGUARD("AdGuard · режет рекламу", "https://dns.adguard-dns.com/dns-query"),
    CLOUDFLARE("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    GOOGLE("Google", "https://dns.google/dns-query"),
    QUAD9("Quad9 · блокирует malware", "https://dns.quad9.net/dns-query")
}
