# Security policy and responsible use

## Intended scope

This tool is for passive DNS lookups and low-impact HTTP/HTTPS reconnaissance on targets for which
you have explicit authorization. Each run requires `--authorized`. That acknowledgment does not
replace written permission or the target owner's rules of engagement.

The tool does not brute-force DNS names, fuzz routes, submit forms, authenticate, send exploit
payloads, perform vulnerability exploitation, or follow redirects. It checks a short list of
standard metadata and API-documentation locations, reads at most 256 KiB from a response, and keeps
endpoint links as evidence without requesting them. Redirect destinations are recorded as
same-origin or out-of-scope and are never fetched automatically.

## Data handling

JSON and CSV reports can reveal target DNS records, software hints, and endpoint paths. Keep real
reports private. This repository ignores generated reports. The HTTP collector never stores page
bodies, `Set-Cookie` values, query strings, or authorization credentials. It records only selected
response headers, bounded technology matches, and cookie attribute flags.

## Reporting an issue

Do not include private target details, scan results, authorization documents, or credentials in a
public issue. Contact the repository maintainer privately with a concise description and reproduction
steps using a test domain you control.
