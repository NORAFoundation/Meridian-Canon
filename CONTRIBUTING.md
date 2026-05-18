# Contributing to Meridian-Canon

Meridian-Canon is a **proprietary specification with open peer review**.
The Work is licensed for reading, citation, and commentary only — see
[LICENSE](LICENSE). Implementation, redistribution, derivative
specifications, and commercial use require a separate written license
from NORA Foundation.

We actively invite — and depend on — public peer review of the
specification, the cryptographic design, the schema, and the
reference implementation. The proprietary license is not a
disengagement from the public; it is a guarantee that the canonical
spec stays canonical while every weakness in it is found in the open.

---

## How to participate

### Report errata or find problems → **GitHub Issues**

High-value Issues:

- Cryptographic critique of the signing flow, canonicalization, or
  hash-chain construction
- Schema gaps or ambiguity in `canon.schema.json` or the attestation
  tables under `schema/`
- Edge cases or counterexamples in the seven-step verification protocol
- Adversarial scenarios that defeat or weaken the falsifiability claim
- Discrepancies between the specification text, the schema, and the
  reference implementation
- Citation errors, out-of-date statutory references, or jurisdictional
  oversights
- Threat-model gaps (Byzantine custodians, compromised keys, side-channel
  leakage)

### Propose changes → **Pull Requests**

High-value PRs:

- Specification clarifications and disambiguation
- Schema corrections and added constraints
- Documentation improvements
- New test vectors, especially adversarial ones
- Reference-implementation fixes that preserve spec conformance
- Worked examples demonstrating a property of the spec

### Discuss design → **GitHub Discussions**

Use Discussions for open-ended questions:

- Protocol design rationale
- Threat models and assumptions
- Governance and conformance criteria
- "Why this and not that" debates
- Comparison with adjacent standards (W3C VC, C2PA, COSE, JOSE, etc.)

---

## ⚠ READ THIS BEFORE SUBMITTING — Contributor Terms

By opening any **Issue, Discussion, comment, or Pull Request** in this
Repository, you agree to the Contributor Terms in **Section 3 of the
[LICENSE](LICENSE)**. In summary:

1. **License grant.** You irrevocably license your Contribution to
   NORA Foundation under a worldwide, perpetual, royalty-free,
   sublicensable license — including the right to **relicense** your
   Contribution under any terms, proprietary or otherwise.
2. **Patent grant.** Any patent claims you control that read on your
   Contribution or on the Work as incorporating it are licensed,
   irrevocably and royalty-free, to NORA Foundation and its licensees.
3. **Originality.** You represent that the Contribution is your
   original work, or work you are authorized to submit.
4. **No obligation to you.** NORA Foundation owes you no merge,
   attribution, acknowledgment, or compensation. Contributors may, at
   NORA Foundation's discretion, be listed in `CONTRIBUTORS.md`.
5. **Moral rights waived** to the extent permitted by applicable law.

This is a hard requirement and applies automatically to every
submission. **If you cannot or will not grant these rights, please do
not submit.** Reading the spec without contributing is always fine
under Section 2(a)–(b) of the LICENSE.

These terms exist because Meridian-Canon is the canonical
specification for NORA-issued attestations. Fragmented or
unrelicensable contributions would prevent the spec from evolving
under a single authoritative source.

---

## Style and hygiene

- **Never** include personal data, real case identifiers, real names,
  or identifying file paths in examples. Use synthetic identifiers:
  `EXAMPLE-MATTER-001`, `user@example.com`, `Custodian-A`, etc.
- Use Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`,
  `spec:`, `chore:`.
- Cryptographic proposals must include a stated threat model and at
  least one worked example or test vector.
- Spec changes should be accompanied by a delta in `canon.schema.json`
  and a corresponding test vector wherever testable.
- Keep PRs focused. One conceptual change per PR.

---

## Review process

See [GOVERNANCE.md](GOVERNANCE.md) for the decision process, the
distinction between normative and informative changes, and the
escalation path.

Substantive objections during the public-comment period must be
on-record in the relevant Issue or PR thread, must state a specific
failure mode or a concrete alternative, and will receive a written
disposition from the Editor-in-Chief before merge.

---

## Security issues — DO NOT FILE PUBLICLY

If you believe you have found a vulnerability in the spec, the schema,
or the reference implementation (key handling, signature verification,
canonicalization, hash-chain integrity, RLS bypass, etc.), do not open
a public Issue.

Email **security@norafoundation.io** with details. We will acknowledge
within 7 days and coordinate a disclosure timeline. Responsible
researchers will be credited (at their option) in the security
advisory.

---

## What we will not accept

- PRs that loosen or remove proprietary-license terms
- PRs that re-license, dual-license, or add an SPDX header asserting
  a different license
- PRs that introduce specification text or implementation derived from
  third-party works whose licenses are incompatible with relicensing
  under our terms
- PRs that scrape, copy, or paraphrase from competing standards (W3C
  VC, C2PA, COSE, JOSE, etc.) in a way that would create derivative-work
  liability
- "Drive-by AI-generated" PRs with no demonstrated understanding of the
  spec
- PRs introducing personal data of any party, real or alleged

---

## What we owe you

- A clear, public answer on every substantive Issue.
- A written disposition on every substantive objection to a normative
  change.
- Credit, at your option, in `CONTRIBUTORS.md` and (for security
  reports) in published advisories.
- Honest engagement. If your critique is correct, the spec changes.
  The spec is for the world; the authority over the spec is NORA
  Foundation's. Those two things are not in tension — they are the
  design.

— NORA Foundation
