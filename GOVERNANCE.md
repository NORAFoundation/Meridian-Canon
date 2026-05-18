# Governance

Meridian-Canon is governed by NORA Foundation. The design intent is a
single authoritative specification, evolved in the open under public
peer review. This document describes who decides, how decisions are
made, and how to escalate.

---

## Roles

### Editor-in-Chief

- **J. Patrick White**, on behalf of NORA Foundation.
- Final authority over the normative content of the specification.
- Sole authority to approve a normative change.

### Maintainers

- Appointed in writing by the Editor-in-Chief.
- May review, merge, or close Issues and PRs that are **informative**
  (documentation, comments, examples, non-normative tests,
  reference-implementation hygiene).
- May **triage** normative proposals but cannot merge them without
  Editor-in-Chief approval.
- Current maintainers are listed in `MAINTAINERS.md` (when present).

### Reviewers

- **Anyone.** Public peer review is the design intent of this repository.
- Reviewers participate by opening Issues, PRs, and Discussions
  under the [CONTRIBUTING.md](CONTRIBUTING.md) terms.

---

## Normative vs. informative

A change is **normative** if it affects how a Conformant Implementation
must behave. Examples:

- Any change to `canon.schema.json` (added / removed / renamed fields,
  changed constraints, changed types)
- Any change to the canonicalization rules, the hashing algorithm,
  the signing algorithm, or the verification protocol
- Any change to the seven-step falsification protocol or its
  acceptance criteria
- Any change to the attestation table contracts in `schema/A0_*.sql`,
  `schema/A1_*.sql`, etc.
- Any change to mandatory error / verdict codes
- Any change to the conformance criteria themselves

A change is **informative** if it does not affect Conformant
Implementation behavior. Examples:

- Documentation rewrites, typo fixes, link updates
- Reference-implementation refactors that preserve the externally
  observable contract
- Internal tests that don't define normative test vectors
- README and tooling improvements

When in doubt, the Editor-in-Chief decides.

---

## Decision process

### Informative changes

1. Open an Issue or PR.
2. A maintainer reviews and may merge once tests pass and the change
   is reviewed.
3. No public-comment period required.

### Normative changes

1. Open an Issue with the label `normative-proposal` describing the
   problem, the proposed change, and at least one worked example or
   test vector.
2. The Editor-in-Chief responds within a target of **14 days**
   acknowledging or rejecting the proposal as a candidate for normative
   change. Rejection here means "not pursued"; a contributor may rework
   and resubmit.
3. Accepted candidates open a **public-comment period** of at least
   **14 calendar days** during which a PR is open and tagged
   `public-comment`. The PR head is the proposed normative text.
4. Substantive objections must be filed in the PR thread. A
   substantive objection states a specific failure mode or proposes a
   concrete alternative; bare disagreement does not suffice.
5. The Editor-in-Chief publishes a **written disposition** for every
   substantive objection — either accepting it (with the resulting
   change), rejecting it (with stated reasoning), or deferring it
   (with a referenced follow-up Issue).
6. After dispositions are recorded, the Editor-in-Chief merges or
   declines the PR.
7. Merged normative changes increment the specification version
   per semantic versioning:
   - **Major** — backward-incompatible change to wire format or
     verification semantics.
   - **Minor** — backward-compatible addition (new optional field,
     new optional verdict reason).
   - **Patch** — clarification with no observable behavioral change.

### Emergency changes

Security vulnerabilities (see [CONTRIBUTING.md § Security issues](CONTRIBUTING.md))
may be patched out-of-band by the Editor-in-Chief without a public-comment
period. A retrospective public disposition is published within 30 days of
disclosure.

---

## Conformance

A **Conformant Implementation** of Meridian-Canon requires all of the
following:

1. A separate written license from NORA Foundation under
   [LICENSE Section 4](LICENSE).
2. Passing the canonical test vectors under
   `meridian/canon/tests/` for the spec version claimed.
3. Listing on the NORA Foundation Conformance Registry (when
   established).

Implementations that pass the test vectors but lack a license from
NORA Foundation are **not** Conformant and may not represent
themselves as such. Use of the marks "NORA Canon," "Meridian-Canon,"
"Canon Attestation," or "Canon-conformant" without authorization is
trademark misuse and a violation of the LICENSE.

---

## Forking on GitHub

Forking this Repository on GitHub for the **specific and limited
purpose** of preparing and submitting a Pull Request is an authorized
use under LICENSE § 2(c) (Comment). Such a fork must:

- Retain the LICENSE, NOTICE, CONTRIBUTING.md, and GOVERNANCE.md files
  unmodified.
- Be deleted or made private once the PR is resolved (merged or
  closed), unless the contributor maintains it as an active branch
  for ongoing peer-review proposals.
- Not be used for any other purpose — including but not limited to
  hosting documentation, training models, advertising a competing
  implementation, or distributing the Work.

Any other forking, mirroring, or copying requires a separate license.

---

## Amendments

This document may be amended by the Editor-in-Chief. Material
amendments to the decision process will be announced in a Discussion
thread and entered into effect no sooner than 14 days after
announcement.
