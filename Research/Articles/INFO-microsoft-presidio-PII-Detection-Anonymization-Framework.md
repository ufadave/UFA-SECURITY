---
title: INFO-microsoft-presidio-PII-Detection-Anonymization-Framework
date: 2026-06-19
source: "https://github.com/microsoft/presidio"
tags:
  - "#resource"
  - "#status/draft"
---

# INFO -- Microsoft Presidio: Open-Source PII Detection & Anonymization Framework

**Source:** https://github.com/microsoft/presidio
**Date:** 2026-06-19
**Author:** Microsoft (open source, MIT licensed)

---

## What It Is

Microsoft's open-source framework for detecting, redacting, masking, and anonymizing
personally identifiable information (PII) across text, images, and structured data.
Supports NLP-based entity recognition, regex pattern matching, and fully customizable
detection and anonymization pipelines. Python-based, embeddable in scripts and data
pipelines.

**Distinct from Microsoft Purview:** Presidio is a code-level library for building
custom PII handling into scripts and applications -- not a managed M365 DLP service.
Purview DLP (available in E5) handles M365-native DLP policy enforcement in SharePoint,
Teams, Exchange, and Copilot. Presidio fills the gap for ad hoc or scripted PII
detection outside the Purview policy engine.

**Core capabilities:**
- Named entity recognition (NER) for PII: names, emails, credit cards, SSNs, phone
  numbers, passport numbers, IP addresses, and more
- Customizable recognizers for org-specific identifiers
- Multiple anonymization strategies: redaction, masking, replacement, hashing, encryption
- Works across unstructured text, CSV/JSON structured data, and images (OCR-based)
- Supports custom NLP models (spaCy, Stanza, transformers)

---

## Relevance

Low-Medium -- a useful tool for specific scripted scenarios rather than core
security operations. Potential applications in this environment:

- **Sanitizing incident/investigation data before external sharing** -- e.g., stripping
  PII from CSV exports before sharing with a vendor, MSSP, or for a CISA report. Could
  complement or replace regex-based anonymization in existing export scripts.
- **Pre-processing AI tool inputs** -- given the active AI Acceptable Use Policy and
  Codex/ChatGPT deployments, Presidio could be used to scrub PII from data before it
  is submitted to external AI APIs.
- **Custom PII discovery in unstructured data** -- for scripted scanning of data stores
  outside the Purview DLP scope.

**Not a replacement for Purview DLP** -- Purview is the enterprise-grade managed DLP
already available in the E5 stack. Presidio is complementary tooling for scenarios
Purview doesn't directly address (custom scripts, external pipelines, non-M365 data).

---

## Actions

- [ ] File as reference for future custom data-sanitization tooling needs
- [ ] Evaluate as a potential PII-stripping layer for AI tool input pre-processing
  (Codex, ChatGPT) if sensitivity label coverage proves insufficient
- [ ] No immediate action required

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-19 | Created -- filed as reference; potential complement to Purview DLP for custom/scripted scenarios |
