# ICS Triage scoring and disclosure timelines

## Scoring formula

```
ICS score = CVSS base score
           + exploit_complexity bonus
           + operational_impact bonus
           + exposure bonus
           + PoC bonus
           + KEV bonus          (CISA Known Exploited Vulnerabilities)
           + EPSS bonus         (exploitation probability)
```

### Bonuses

| Source   | Field / condition                                     | Bonus |
|----------|-------------------------------------------------------|------:|
| Input    | `exploit_complexity: low`                             |  +2.0 |
| Input    | `exploit_complexity: medium`                          |   0.0 |
| Input    | `exploit_complexity: high`                            |  −2.0 |
| Input    | `operational_impact: safety hazard`                   |  +3.0 |
| Input    | `operational_impact: process halt`                    |  +2.0 |
| Input    | `operational_impact: service disruption`              |  +1.0 |
| Input    | `operational_impact: none`                            |   0.0 |
| Input    | `exposure: internet`                                  |  +2.0 |
| Input    | `exposure: internal network`                          |  +1.0 |
| Input    | `exposure: vpn only`                                  |   0.0 |
| Input    | `exposure: serial port`                               |  −1.0 |
| Input    | `poc_available: true`                                 |  +1.0 |
| CISA KEV | CVE is in the Known Exploited Vulnerabilities catalog |  +2.0 |
| EPSS     | Exploitation probability > 50 %                       |  +1.0 |

Zero-days without a CVSS score start at 0. Use `cvss_score` in the input to provide a self-assessed score.

CVSS is pulled from MISP enrichment (`cve` module → cve.circl.lu) when not provided in the input and a CVE ID is present.

## Decision table (example)

| ICS score                   | Decision                | Deadline |
|-----------------------------|-------------------------|----------|
| ≥ 9                         | DISCLOSE NOW            | 30 days  |
| 7 – 8.9                     | DISCLOSE WITHIN 60 DAYS | 60 days  |
| 4 – 6.9                     | DISCLOSE WITHIN 90 DAYS | 90 days  |
| > 0                         | MONITOR                 | —        |
| 0                           | MANUAL REVIEW           | —        |
| `disclosure_status: public` | ALREADY PUBLIC          | —        |

Deadline dates are computed from the date the workflow runs (UTC).

Rankings are sorted first by decision urgency (DISCLOSE NOW before 60 DAYS, etc.), then by descending ICS score within each tier.

## ENISA CVD framework

Disclosure drafts follow the [ENISA Coordinated Vulnerability Disclosure guide](https://www.enisa.europa.eu/topics/vulnerability-disclosure)

Each draft includes:

- Vulnerability ID, title, product, CVSS score, CWE, impact description
- Deadline date
- National CERT in CC (mapped from vendor country)
- VDE CERT in CC (German ICS coordinator, active across EU)

## Notification routing

| Vendor country                                                            | National CERT   | CC on all drafts |
|---------------------------------------------------------------------------|-----------------|------------------|
| Germany (Siemens, Beckhoff, Pilz, Bosch, Lenze, CODESYS, Phoenix Contact) | BSI CERT-Bund   | VDE CERT         |
| France (Schneider Electric)                                               | CERT-FR / ANSSI | VDE CERT         |
| Netherlands (Philips)                                                     | NCSC-NL         | VDE CERT         |
| Switzerland (ABB, Endress+Hauser)                                         | NCSC-CH         | VDE CERT         |
| Sweden (HMS Networks)                                                     | NCSC-SE         | VDE CERT         |
| Other / unknown                                                           | ENISA           | VDE CERT         |

For vendors not in the built-in table, the workflow guesses the PSIRT email as
`security@<vendor>.com` and falls back to ENISA as the national coordinator.
Update `EU_PSIRTS` in the workflow code for accurate routing.