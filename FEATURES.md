# ECDAT Feature Guide

This document explains the main capabilities added to ECDAT and how they are intended to work in practice. The goal is to make the tool understandable for internal security engineering teams, external-facing product teams, and mixed environments.

## 1. Internal scanning

Internal scanning is used when the codebase or asset inventory is mostly behind internal systems, administrative boundaries, or operational tooling.

What it does:
- Identifies cryptographic use in internal services, admin flows, worker jobs, infrastructure configuration, and data-processing pipelines.
- Favors internal path heuristics when the scan is not explicitly marked as external.
- Treats in-house operational systems as lower exposure than public customer paths unless the data is highly sensitive.

Why it matters:
- Internal systems often handle long-lived operational secrets, service-to-service encryption, and environment-level certificate material.
- They may not be exposed to end users, but they still require secure migration planning and key rotation.

Typical examples:
- internal admin dashboards
- microservices behind a gateway
- batch-processing jobs
- CI/CD, deployment, and infrastructure repositories

## 2. External scanning

External scanning is used when the code or service is directly exposed to users, partners, external APIs, or internet-facing traffic.

What it does:
- Prioritizes external boundary classification for public APIs, clients, edge services, gateways, storefronts, and customer-facing flows.
- Increases the urgency of migration for assets on public surfaces because they are more likely to be attacked and more expensive to replace safely.
- Sends stronger recommendation weighting toward hybrid or compatibility-aware migration plans.

Why it matters:
- External systems handle internet traffic, user secrets, payment data, tokens, session material, and public API surfaces.
- The impact of a vulnerable algorithm is higher because the blast radius includes customer trust, compliance exposure, and operational downtime.

Typical examples:
- public web apps
- checkout flows
- edge gateways
- client-side integrations exposed to the internet

## 3. Mixed scanning

Mixed scanning is used when a project contains both internal and external surfaces or when the environment is not clearly one or the other.

What it does:
- Keeps the scan conservative by not assuming the whole project is only internal or only external.
- Uses a combination of file-path heuristics and explicit scan configuration to classify assets by their boundary.
- Allows teams to separately reason about public-facing components and internal-only cryptographic material in the same inventory.

Why it matters:
- Most enterprises have layered architectures: public platforms, internal tooling, shared services, and operational infrastructure.
- Mixed classification gives a realistic picture without over- or under-prioritizing assets.

Typical examples:
- monorepos with APIs and internal admin modules
- systems with web front ends plus internal jobs and data orchestration
- hybrid SaaS environments spanning external customers and internal back-office services

## 4. Risk logic in plain language

ECDAT evaluates crypto findings across several dimensions:
- whether the algorithm is quantum-vulnerable
- whether it is already broken classically
- how long the protected data must remain secret
- how long migration takes
- what year a cryptographically relevant quantum computer is expected to arrive
- whether the crypto sits in a public or internal system

The tool then calculates a Mosca-style urgency score and assigns a risk tier. This is not just a raw algorithm match; it is a business-aware risk assessment.

## 5. Cost logic and why it exists

The roadmap cost is expressed in Indian rupees so it better matches enterprise planning in India, especially for security teams calculating migration budgets.

The cost estimate covers:
- engineering investigation and impact analysis
- algorithm replacement design
- code changes and library upgrades
- regression testing and compatibility validation
- certificate rotation or key replacement
- rollout and deployment coordination
- operational signoff and re-scan verification

This is why the output is presented as an indicative estimate rather than a final quote. It is meant to support planning, prioritization, and project budgeting.

## 6. Security impact of the added features

These features improve the tool by making it realistic for real-world organizations:
- Internal/external classification improves risk prioritization.
- Mixed classifications avoid false confidence in monolithic architectures.
- Explicit cost estimates in INR make budget planning easier for Indian teams.
- The roadmap now explains both the urgency and the reason the cost exists.

This gives teams a clearer understanding of where to invest first and why.
