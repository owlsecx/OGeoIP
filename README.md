# 🦉 OGeoIP

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Recon%20/%20OSINT-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OGeoIP** — Offline IP geolocation (MaxMind MMDB engine) · scope · rDNS · ASN/BGP ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OGeoIP — Offline IP geolocation (MaxMind MMDB engine) · scope · rDNS · ASN/BGP. IP Geolocation · rDNS · ASN (offline MaxMind engine) Geolocates IP addresses fully offline by reading a MaxMind GeoLite2/GeoIP2 .mmdb database directly: a from-scratch MMDB reader (binary search tree + data-section decoder, record sizes 24/28/32, IPv4-in-IPv6 handling) with no third-party libraries and no HTTP geolocation API. Adds scope/reserved classification (RFC 1918/6598/5737/…), forward & reverse DNS, and ASN / BGP-prefix lookups via the Team Cymru DNS service.

---

## ✨ Features

- Offline MaxMind MMDB reader (no third-party geo API)
- IPv4/IPv6 lookup with language selection and bulk mode
- Scope classification (private/reserved/global) plus rDNS helpers
- ASN/BGP-oriented fields when present in the database
- Database info introspection and self-test
- JSON output for scripting and enrichment pipelines

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OGeoIP OGeoIP.go
./OGeoIP --help
./OGeoIP --ip 8.8.8.8 --db GeoLite2-City.mmdb
./OGeoIP --bulk ips.txt --db GeoLite2-City.mmdb --json
./OGeoIP --dbinfo --db GeoLite2-City.mmdb
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

**GNU General Public License v3.0** — © 2026 Owlsec LLC

This tool is free software: its full source code is published in this repository and you may study, modify and redistribute it under the GPL-3.0.

> Other OwlSec tools are separate, independent programs under their own terms; many remain proprietary.
