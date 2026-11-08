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
[clean        0] 01-legit-newsletter.eml: news@example.com (spf=pass dkim=pass dmarc=pass, 0 indicators)
[malicious  140] 02-bec-ceo-spoof.eml: ceo@example.com (spf=fail dkim=none dmarc=fail, 8 indicators)
[malicious  185] 03-brand-lookalike.eml: security@micros0ft-billing.example (spf=softfail dkim=fail dmarc=fail, 8 indicators)
[suspicious  45] 04-macro-attachment.eml: accounts@example-vendor.example (spf=pass dkim=pass dmarc=none, 2 indicators)
[clean       10] 05-internal-no-auth.eml: it@example.org (spf=none dkim=none dmarc=none, 2 indicators)
Analysed 5 messages: 2 malicious, 1 suspicious, 2 clean.
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

The `samples/` folder is synthetic and safe to run. Five messages cover a clean
newsletter, a CEO impersonation with a double extension, a brand lookalike with an
IP address link, a macro document, and an internal note with no auth headers.

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
samples/                             synthetic .eml fixtures
tests/                               unit and end to end tests
```

## Tests

```bash
python -m pytest -q
python -m ruff check .
```

16 tests cover header parsing, auth result parsing, the Received-SPF fallback,
indicator extraction, scoring thresholds, report output, and the CLI exit codes.
CI runs them on Ubuntu and Windows with Python 3.11 and 3.12.

## License

MIT. See LICENSE.
