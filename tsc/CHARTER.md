# Technical Charter for DNS-AID Project

Adopted: January 2026

This Technical Charter sets forth the responsibilities and procedures for technical contribution to, and oversight of, the DNS-AID open source project (the "Project"). Contributors to the Project must comply with the terms of this Charter.

## 1. Mission and Scope

The mission of the Project is to provide a reference implementation and open-source toolkit for DNS-based Agent Identification and Discovery (DNS-AID), as specified in IETF draft-mozleywilliams-dnsop-bandaid. The Project enables AI agents to discover each other using existing DNS infrastructure, without centralized registries.

The scope includes:

- Core protocol library (publish, discover, verify)
- DNS backend implementations (Route 53, Cloudflare, DDNS, Infoblox, etc.)
- CLI tool for operators
- MCP server for AI agent integration
- Documentation, examples, and test suites
- Alignment with IETF BANDAID draft specifications

## 2. Technical Steering Committee (TSC)

The TSC is responsible for all technical oversight of the Project. Initially, the TSC comprises the Project's Committers as defined in [GOVERNANCE.md](../GOVERNANCE.md).

### TSC Responsibilities

- Setting the technical direction of the Project
- Approving project releases
- Creating sub-projects or working groups
- Managing the project's relationship with the IETF BANDAID draft
- Ensuring alignment with Linux Foundation policies
- Resolving technical disputes

### TSC Voting

- Each TSC member has one vote
- Decisions require a simple majority of voting members
- A quorum of two-thirds of TSC members is required for votes
- The TSC Chair has the casting vote in case of a tie

## 3. TSC Chair

The TSC will elect a Chair from among the TSC members. The Chair will:

- Preside over TSC meetings
- Serve as the primary liaison with the Linux Foundation
- Ensure decisions are documented and communicated

## 4. Contributions

### Intellectual Property Policy

- All new inbound code contributions must be made under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- All new inbound code contributions must be accompanied by a Developer Certificate of Origin (DCO) sign-off ([https://developercertificate.org](https://developercertificate.org))
- All outbound code will be made available under the Apache License, Version 2.0
- Documentation will be made available under the Creative Commons Attribution 4.0 International License (CC-BY-4.0)

### Contribution Process

All contributions are made through pull requests reviewed by at least one Committer. See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

## 5. Community Assets

- The Project's GitHub repository and any domain names or trademarks will be transferred to the Linux Foundation upon acceptance
- The Linux Foundation will hold these assets on behalf of the Project community

## 6. General Rules and Operations

The Project will:

- Operate transparently, with discussions and decisions made publicly
- Encourage broad participation from the community
- Follow the [Code of Conduct](../CODE_OF_CONDUCT.md)
- Comply with Linux Foundation policies

## 7. Amendments

This Charter may be amended by a two-thirds vote of the entire TSC, subject to approval by the Linux Foundation.
