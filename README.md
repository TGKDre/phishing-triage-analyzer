# Phishing Triage and Email Auth Analyzer

[![ci](https://github.com/TGKDre/phishing-triage-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/TGKDre/phishing-triage-analyzer/actions/workflows/ci.yml)

Point it at a folder of reported `.eml` files and it tells you which ones are
dangerous and why. It reads the authentication results already stamped on the
message (SPF, DKIM, DMARC), extracts the indicators a triage analyst cares about
(sender identity, links, attachments), scores each message, and writes a CSV plus
a self-contained HTML report for the ticket or the manager.

No tenant, no mailbox access, no credentials. It works on files you already have.

## Why it exists

Reported phishing is the highest volume security task in most small IT shops, and
a lot of triage is mechanical: did DMARC fail, is the reply going somewhere else,
is that link a lookalike, is that attachment a double extension. This turns a pile
of `.eml` files into a ranked list in one command, with the reasons written down
so the next person can check the work.

## Quick start

```bash
python -m pip install -e .
phishing-analyzer --input samples --out reports
```

Output on the bundled synthetic samples:

```
[malicious  140] malicious-bec-ceo-spoof.eml: ceo@example.com (spf=fail dkim=none dmarc=fail, 8 indicators)
[malicious  185] malicious-brand-lookalike.eml: security@micros0ft-billing.example (spf=softfail dkim=fail dmarc=fail, 8 indicators)
[malicious  150] malicious-docusign-punycode.eml: no-reply@docusign.example (spf=pass dkim=pass dmarc=pass, 5 indicators)
[malicious  170] malicious-invoice-archive.eml: ar@example-billing.example (spf=fail dkim=fail dmarc=fail, 7 indicators)
[malicious  115] malicious-mfa-shortener.eml: security@example.net (spf=softfail dkim=none dmarc=none, 8 indicators)
[suspicious  20] risky-forwarded-quote.eml: sam.okafor@example.org (spf=pass dkim=pass dmarc=pass, 2 indicators)
[suspicious  45] risky-macro-attachment.eml: accounts@example-vendor.example (spf=pass dkim=pass dmarc=none, 2 indicators)
[suspicious  20] risky-vendor-payment-change.eml: billing@northwind-supply.example (spf=pass dkim=pass dmarc=none, 2 indicators)
[clean       10] safe-internal-no-auth.eml: it@example.org (spf=none dkim=none dmarc=none, 2 indicators)
[clean        0] safe-newsletter.eml: news@example.com (spf=pass dkim=pass dmarc=pass, 0 indicators)
[clean        0] safe-partner-invoice.eml: finance@contoso.example (spf=pass dkim=pass dmarc=pass, 0 indicators)
[clean        0] safe-password-reset.eml: it@example.com (spf=pass dkim=pass dmarc=pass, 0 indicators)
Analysed 12 messages: 5 malicious, 3 suspicious, 4 clean.
Wrote reports/findings.csv and reports/report.html
```

Options: `--dns` adds live DNS record checks, `--json` writes `results.json`, and
`--fail-on malicious` exits with code 2 when anything reaches that verdict, which
makes it usable as a gate in a pipeline or a share.

## What it checks

Authentication, from the message headers:

- SPF, DKIM and DMARC results, with the domain each one refers to.
- DMARC passed for a domain that is not the visible From domain.
- SPF fail, softfail, or errors.
- Missing DKIM signature.
- DMARC has no result at all, so alignment cannot be confirmed from the file.

Identity:

- Reply-To on a different domain than From, the classic business email compromise tell.
- Display name containing an address that is not the sender.
- Display name claiming a brand (Microsoft, PayPal, DocuSign and similar) on a domain that is not that brand.
- Sender domain that imitates a brand, including one character substitutions.

Links, extracted from the text and HTML parts:

- Raw IP address hosts.
- Punycode hosts.
- URL shorteners.
- Domains one or two edits away from the sender domain.
- Credential and account words in the path on an unrelated domain.
- Plain HTTP.
- Links that download an executable or archive.

Attachments:

- Executable and script types, with the SHA256 hash recorded.
- Double extensions such as `invoice.pdf.exe`.
- Macro-enabled Office documents.
- Archives that can hide a payload.

With `--dns`, it also checks whether the sender domain publishes SPF and DMARC
records, the DMARC policy, and whether the DKIM selector in the signature has a
published key.

## Scoring

Each indicator carries a severity. High is 40 points, medium 15, low 5. The sum
becomes the score:

- 60 and above: malicious
- 20 to 59: suspicious
- below 20: clean

The weights are in `score.py` if you want to tune them for your environment.

## Safety and limits

- It never fetches a link, never opens an attachment, and never executes anything.
  Indicators come from parsing text and hashing bytes.
- It does not detonate attachments in a sandbox. A clean score means nothing was
  flagged, not that the message is safe. A human decision still ends the workflow.
- Header based authentication results are only as good as the receiving MTA that
  stamped them. `--dns` checks records, not full delivery path evaluation. It does
  not re run SPF against the connecting IP.
- This is a triage assistant, not a mail gateway. It is designed to be run after
  the fact on messages a user reported.

## Input

Any `.eml` file, or a directory that is searched recursively for `.eml` and
`.msg` files. Standard RFC 5322 messages exported from Outlook, Gmail, or a
gateway all work. Headers are read as they appear, including multiple
`Authentication-Results` headers.

The `samples/` folder is a synthetic corpus, safe to open, run, and commit. Every
file is named for the band it belongs in, and the test suite pins each one to its
expected verdict, so a rule change that flips a classification fails CI.

| File | Band | What it exercises |
| --- | --- | --- |
| `malicious-bec-ceo-spoof.eml` | malicious | DMARC fail, Reply-To mismatch, double extension, credential link |
| `malicious-brand-lookalike.eml` | malicious | Brand lookalike sender, softfail, raw IP link, brand display name |
| `malicious-docusign-punycode.eml` | malicious | Authenticated but fake brand domain, punycode link, credential path |
| `malicious-invoice-archive.eml` | malicious | Triple auth failure, IP link that downloads an archive, zip attachment |
| `malicious-mfa-shortener.eml` | malicious | Display name carrying an address, shortener, lookalike MFA page |
| `risky-forwarded-quote.eml` | risky | Aligned mail with an archive attachment and plain HTTP link |
| `risky-macro-attachment.eml` | risky | Macro document on a domain with no DMARC policy |
| `risky-vendor-payment-change.eml` | risky | Bank detail change with Reply-To on a different domain, no DMARC |
| `safe-internal-no-auth.eml` | safe | Internal note with no auth headers, low findings only |
| `safe-newsletter.eml` | safe | Fully aligned newsletter, zero indicators |
| `safe-partner-invoice.eml` | safe | Aligned vendor mail with a clean PDF attachment |
| `safe-password-reset.eml` | safe | Legitimate reset link on the sender's own domain |

Band meanings: `malicious` is the malicious verdict, `risky` is the suspicious
verdict, and `safe` is the clean verdict.

## Structure

```
src/phishing_analyzer/models.py      data types
src/phishing_analyzer/parse.py       .eml parsing and header extraction
src/phishing_analyzer/auth.py        SPF, DKIM and DMARC from headers
src/phishing_analyzer/indicators.py  URLs, attachments, identity checks
src/phishing_analyzer/dns_check.py   optional live DNS record checks
src/phishing_analyzer/analyze.py     orchestration, scoring and JSON export
src/phishing_analyzer/report.py      CSV and HTML output
src/phishing_analyzer/cli.py         command line entry point
samples/                             synthetic .eml corpus (malicious, risky, safe)
tests/                               unit, end to end and corpus tests
```

## Tests

```bash
python -m pytest -q
python -m ruff check .
```

The suite covers header parsing, auth result parsing, the Received-SPF fallback,
indicator extraction, scoring thresholds, report output, and the CLI exit codes.
A corpus manifest additionally pins all 12 bundled samples to their expected
verdict and filename band, so a rule change that flips a classification fails
the build. CI runs the suite on Ubuntu and Windows with Python 3.11 and 3.12.

## License

MIT. See LICENSE.
