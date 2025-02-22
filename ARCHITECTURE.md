# Architecture

> [!CAUTION]
> Pre-alpha, subject to change. Do not rely on this for anything.

> Architectural overview for this project. WIP

## Scanner to Assessor Architecture

Here's a summary of the Scanner to Assessor architecture, designed for easy planning and export:

### Scanner Summary (Scan Phase - Data Collection)

| Scanner Name            | Function                                        | Record Types Scanned (if applicable)                              | Enumeration Types (if applicable)                    |
|-------------------------|-------------------------------------------------|-------------------------------------------------------------------|------------------------------------------------------|
| DomainResolver          | Retrieves all relevant DNS records for a domain | A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA, DS, DNSKEY, etc. | N/A                                                  |
| SubdomainEnumeration    | Discovers subdomains for a given domain         | N/A (Pipes to DomainResolver for record retrieval)                | Brute-forcing, Dictionary Attacks, Passive DNS, etc. |
| CertificateScanner      | Retrieves SSL/TLS certificate information       | N/A (Infers domains from A/AAAA or input list)                    | N/A                                                  |
| DNSSecScanner           | Probes for DNSSEC status & related records      | DNSKEY, DS                                                        | N/A                                                  |
| ZoneTransferScanner     | Attempts AXFR/IXFR zone transfers               | NS Records (to find nameservers)                                  | N/A                                                  |
| ServiceDiscoveryScanner | Basic port scan for web/mail services           | A, AAAA (from DomainResolver), MX (for mail servers)              | N/A                                                  |
| PassiveDNSSourceScanner | Enriches data with Passive DNS information      | N/A (Retrieves historical DNS data from external sources)         | N/A                                                  |

### Assessor Summary (Assess Phase - Analysis & Judgment)

#### I. Security Assessors (Vulnerability & Threat Focused)

| Assessor Name            | Function                                                              |
|--------------------------|-----------------------------------------------------------------------|
| DanglingCNAMEAssessor    | Detects dangling CNAME records and potential subdomain takeover risks |
| ZoneTransferAssessor     | Flags domains vulnerable to unauthorized zone transfers (AXFR/IXFR)   |
| DNSSecAssessor           | Assesses DNSSEC deployment status and identifies misconfigurations    |
| SPFRecordAssessor        | Evaluates SPF record configuration for email spoofing risks           |
| DKIMRecordAssessor       | Checks for DKIM record presence and key configuration                 |
| DMARCRecordAssessor      | Evaluates DMARC policy strength and reporting configuration           |
| OpenPortAssessor         | Flags unexpected or risky open ports associated with domain IPs       |
| CNAMERedirectionAssessor | Detects CNAME loops, long chains, and CNAME records pointing to IPs   |
| NSConfigurationAssessor  | Detects NS record changes and assesses nameserver legitimacy          |
| CAAConfigurationAssessor | Assesses CAA record presence and Certificate Authority configurations |

#### II. Operational Assessors (Reliability, Performance, Functionality Focused)

| Assessor Name                    | Function                                                                  |
|----------------------------------|---------------------------------------------------------------------------|
| DNSResolutionConsistencyAssessor | Detects inconsistencies in DNS responses from different resolvers         |
| DNSResolutionLatencyAssessor     | Monitors and flags domains/record types with slow DNS resolution times    |
| NameserverReachabilityAssessor   | Monitors the availability and responsiveness of authoritative nameservers |

#### III. Compliance & Best Practices Assessors (Policy & Standard Adherence Focused)

| Assessor Name                | Function                                                                     |
|------------------------------|------------------------------------------------------------------------------|
| DNSSECComplianceAssessor     | Assesses DNSSEC deployment against best practices and compliance standards   |
| EmailAuthComplianceAssessor  | Evaluates email authentication (SPF, DKIM, DMARC) against best practices     |
| CAAComplianceAssessor        | Checks CAA record implementation against certificate security best practices |
| ZoneTransferSecurityAssessor | Verifies zone transfer restrictions align with security best practices       |
| NameserverRedundancyAssessor | Recommends/assesses nameserver redundancy and distribution                   |
| MinimumRecordSetAssessor     | Ensures essential DNS records are present for core services                  |

---

## Specific Scanners/Assessors

### CNAME 

A break-down of the CNAME record scanner. This vulnerability requires several checks split across multiple scanners,
and assessors. Many of these assessors will be *active*, that is, make network requests to the target domain - at
time of writing.

A lot of inspiration for this scanner came from the [dnsReaper](https://github.com/punk-security/dnsreaper) project.

| DNSReaper Check                                         | Recommended Phase | Rationale                                                                                                                                                                                                                        | Type of Network Activity       |
|---------------------------------------------------------|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|
| 1a. CNAME Lookup (DNS Resolution Checks)                | **Scan Phase**    | This is a basic DNS query to get the CNAME record itself. Essential initial data collection and very lightweight.                                                                                                                | DNS Query (UDP/TCP)            |
| 1b. A/AAAA Lookup (DNS Resolution Checks)               | **Scan Phase**    | Also a basic DNS query to resolve the CNAME target.  Crucial initial data for determining if the target *resolves*. Still lightweight data collection.                                                                           | DNS Query (UDP/TCP)            |
| **1c. "Potentially Dangling" Determination** (If no IP) | **Assess Phase**  | The *interpretation* of "no IP resolution" as *potentially dangling* is an **assessment**. The Scan phase just collects the resolution data. The Assessor makes the judgment based on the data.                                  | N/A                            |
| 2. Cloud Provider-Specific Checks (All Sub-Checks)      | **Assess Phase**  | These checks are more complex, resource-intensive, and service-specific. They involve active probing of cloud provider endpoints and APIs.  Best suited for the Assess Phase where targeted active checks are performed.         | HTTP/HTTPS Requests, API Calls |
| 3. HTTP/HTTPS Checks (HTTP/HTTPS Request to Target)     | **Assess Phase**  | Sending HTTP/HTTPS requests is active network probing.  These checks are necessary for deeper verification, especially if DNS resolution fails or points to cloud services.  Keep in Assess Phase for controlled active probing. | HTTP/HTTPS Requests            |
| 4. Wildcard DNS Detection                               | **Assess Phase**  | This is an *analysis* of DNS resolution behavior.  You need to compare resolutions of the CNAME target with wildcard resolutions.  This is data analysis and belongs in the Assess Phase.                                        | N/A (Data Analysis)            |
| 5. Provider-Specific API Checks                         | **Assess Phase**  | Explicitly using cloud provider APIs is active interaction and authentication (if needed). Definitely Assess Phase for targeted API calls.                                                                                       | API Calls (HTTPS)              |
| 6. Custom Error Page Detection                          | **Assess Phase**  | Analyzing HTTP/HTTPS response content for specific error pages is an *interpretation* of the response data.  It's part of the assessment logic, not core scanning.                                                               | N/A (Data Analysis)            |kk