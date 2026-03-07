# Disclosure contacts

## EU ICS / OT coordinator

| Organisation | Role                                                               | Contact          |
|--------------|--------------------------------------------------------------------|------------------|
| CERT@VDE     | German ICS security coordinator; active across EU; listed by ENISA | info@certvde.com |

CERT@VDE is CC'd on every disclosure draft regardless of vendor country.

## EU national CERTs

| CERT              | Country / scope                 | Email                          |
|-------------------|---------------------------------|--------------------------------|
| BSI CERT-Bund     | Germany                         | certbund@bsi.bund.de           |
| CERT-FR / ANSSI   | France                          | cert-fr@ssi.gouv.fr            |
| NCSC-NL           | Netherlands                     | cert@ncsc.nl                   |
| NCSC-CH / GovCERT | Switzerland                     | incidents@govcert.ch           |
| CERT-SE           | Sweden                          | cert@cert.se                   |
| ENISA             | EU-level coordinator (fallback) | cert-relations@enisa.europa.eu |

The national CERT is selected based on the vendor's headquarters country (see `EU_PSIRTS` in the workflow code).

## Vendor PSIRTs (built-in)

| Vendor             | PSIRT name                 | Email                                                             | National CERT | Verified |
|--------------------|----------------------------|-------------------------------------------------------------------|---------------|----------|
| Siemens            | Siemens ProductCERT        | productcert@siemens.com                                           | BSI           | ✓        |
| Schneider Electric | Schneider Electric CPCERT  | CPCERT@se.com                                                     | CERT-FR       | ✓        |
| ABB                | ABB PSIRT                  | cybersecurity@ch.abb.com                                          | NCSC-CH       | ✓        |
| Philips            | Philips PSIRT              | productsecurity@philips.com                                       | NCSC-NL       | ✓        |
| Phoenix Contact    | Phoenix Contact PSIRT      | psirt@phoenixcontact.com                                          | BSI           | ✓        |
| Beckhoff           | Beckhoff Incident Response | product-securityincident@beckhoff.com                             | BSI           | ✓        |
| Pilz               | Pilz PSIRT                 | security@pilz.com                                                 | BSI           | ✓        |
| Bosch Rexroth      | Bosch PSIRT                | psirt@bosch.com                                                   | BSI           | ✓        |
| Endress+Hauser     | Endress+Hauser PSIRT       | info@endress.com  ???                                             | NCSC-CH       | ?        |
| HMS Networks       | HMS Networks Security      | (web form) hms-networks.com/cyber-security/report-a-vulnerability | CERT-SE       | ✓        |
| CODESYS            | CODESYS Security           | security@codesys.com                                              | BSI           | ✓        |
| Lenze              | Lenze Security             | psirt@lenze.com                                                   | BSI           | ✓        |

`?` = email not independently confirmed from vendor's public disclosure page; verify before use.

For vendors not in the table, the workflow falls back to a default `security@<vendor>.com` and uses ENISA as the national coordinator. Add entries to `EU_PSIRTS` in the workflow code to improve routing.

## ENISA CVD framework reference

[ENISA Vulnerability Disclosure](https://www.enisa.europa.eu/topics/vulnerability-disclosure)

## Other EU resources

| Resource            | Description                                                                                                                                                |
|---------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CIRCL CVE Search    | [CVE enrichment API used by the workflow](https://cve.circl.lu)                                                                                            |
| ENISA NIS2          | [Network and Information Security Directive 2](https://www.enisa.europa.eu/topics/state-of-cybersecurity-in-the-eu/cybersecurity-policies/nis-directive-2) |
| ICS-CERT Advisories | [US CISA advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) (import manually; no native MISP feed)                                     |
| CERT@VDE advisories | [VDE CERT public advisories](https://certvde.com/en/advisories/)                                                                                           |
