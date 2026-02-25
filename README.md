<p align="center"><img src="https://raw.githubusercontent.com/is-cool-me/register/main/media/icon.png" height="128"></p>
<h1 align="center">is-cool-me</h1>

<p align="center">
  <a href="https://github.com/is-cool-me/register/tree/main/domains"><img src="https://img.shields.io/github/directory-file-count/is-cool-me/register/domains?label=domains&style=for-the-badge&type=file"></a>
  <a href="https://github.com/is-cool-me/register/issues"><img src="https://img.shields.io/github/issues-raw/is-cool-me/register?label=issues&style=for-the-badge"></a>
  <a href="https://github.com/is-cool-me/register/pulls"><img src="https://img.shields.io/github/issues-pr-raw/is-cool-me/register?label=pull%20requests&style=for-the-badge"></a>
</p>

<p align="center">Free subdomains for personal sites, open-source projects, and more.</p>
<p align="center">Want to find services similar to this? Take a look on <a href="https://github.com/open-domains/register">Open Domains</a>.</p>

---

> 🔒 **Need a free SSL certificate?** Check out [**SSLgen**](https://sslgen.mayank.is-a.dev) — a free, web-based SSL certificate generator!

---

## 📢 Notice

> We have moved domains: **is-cool.me → is-pro.dev** and **is-app.tech → is-into.tech**. Please update your services’ DNS, API references, and links accordingly.

## 💖 Donate

If you like this service and want us to continue running it, please consider donating!

## 💬 Discord Server

Join our community Discord server for support and updates:

[![Discord](https://img.shields.io/badge/Join%20Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/N8YzrkJxYy)

## 🌐 Domains

| Available Domains |
|:-:|
| [`*.is-pro.dev`](https://is-pro.dev) |
| [`*.is-into.tech`](https://is-into.tech) |

> **Note:** Wildcard domains (like `*.example.is-pro.dev`) and NS records are supported too, but the reason for their registration should be very clear and described in detail. We currently do **not** support Cloudflare (for NS), Netlify (for websites), or Vercel (for websites).

[badge-cf]:https://shields.io/badge/%20-cloudflare-blue?logo=cloudflare&style=plastic?cacheSeconds=3600
[badge-dnssec]:https://shields.io/badge/%20-DNSSEC-blue?logo=moleculer&logoColor=white&style=plastic?cacheSeconds=3600
[badge-ssl]:https://shields.io/badge/SSL-Required-blue?style=plastic?cacheSeconds=3600

### ⚙️ Settings

| Setting | is-into.tech | is-pro.dev |
|:--------|:------------:|:----------:|
| DNSSEC  | ✅ | ✅ |
| Email   | ✅ | ✅ |
| SSL/TLS\* | Full | Full |
| Always Use HTTPS\* | ✅ | ✅ |
| HTTP Strict Transport Security (HSTS) | ✅ | ✅ |
| Minimum TLS Version\* | 1.2 | 1.2 |
| Opportunistic Encryption, TLS 1.3\* | ✅ | ✅ |
| WAF (Web Application Firewall)\* | Medium Security | Medium Security |
| Browser Integrity Check\* | ✅ | ✅ |
| Caching Level, Browser Cache TTL\* | Standard, 4 hours | Standard, 4 hours |

\*Only available when your domain has Cloudflare's proxy (`"proxied": true`) enabled.

[dnssec]:https://developers.cloudflare.com/dns/additional-options/dnssec
[ssl-full]:https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full
[caching-levels]:https://developers.cloudflare.com/cache/how-to/set-caching-levels

## 📝 Register

### 💻 CLI *(recommended)*

1. Install the CLI:

```bash
npm install @is-cool.me/cli -g
```

2. Login to the CLI:

```bash
ic login
```

3. Register a domain and follow the prompts:

```bash
ic register
```

### ✋ Manual

1. **Star** ⭐ and **[Fork](https://github.com/is-cool-me/register/fork)** this repository.
2. Add a new file called `example.domain.json` in the `/domains` folder to register the `example` subdomain.
3. Edit the file — below is an **example**. Provide a **valid** JSON file matching your needs. The format is strict:

```json
{
    "domain": "is-into.tech",
    "subdomain": "example",

    "owner": {
        "username": "yourgithubusername",
        "email": "hello@example.com"
    },

    "records": {
        "A": ["1.1.1.1", "1.0.0.1"],
        "AAAA": ["2606:4700:4700::1111", "2606:4700:4700::1001"],
        "CNAME": "example.com",
        "MX": [
            {
                "priority": 10,
                "value": "mx1.example.com"
            },
            {
                "priority": 20,
                "value": "mx2.example.com"
            }
        ],
        "TXT": [
            {
                "name": "@",
                "value": "example_verification=1234567890"
            }
        ],
        "CAA": [
            { "flags": 0, "tag": "issue", "value": "letsencrypt.org" },
            { "flags": 0, "tag": "issuewild", "value": "sectigo.com" }
        ],
        "SRV": [
            { "priority": 10, "weight": 60, "port": 5060, "target": "sipserver.example.com" },
            { "priority": 20, "weight": 10, "port": 5061, "target": "sipbackup.example.com" }
        ],
        "PTR": [
            "ptr.example.com"
        ]
    },

    "proxied": false
}
```

4. Your pull request will be reviewed and merged. Please don't ignore the pull request checklist — if you do, your PR may be ignored. _Keep an eye on it in case we need you to make changes!_
5. After the pull request is merged, please allow up to 24 hours for changes to propagate _(usually it takes 5–15 minutes)_.
6. 🎉 Enjoy your new domain!

> ⚠️ Domains used for illegal purposes will be removed and permanently banned. Please provide a clear description of your resource in the pull request.

## 🙏 Credits

Credit for this repo goes to [Open Domains](https://github.com/open-domains/register) and [Free Domains](https://github.com/free-domains/register).

## 📄 License

This project is under a [MIT License](https://github.com/is-cool-me/register/blob/main/LICENSE).
