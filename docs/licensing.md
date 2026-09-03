# Messaging Integration Licensing Gate

The architecture prefers a SimpleX-style asynchronous relay protocol, but the repository must not silently absorb upstream implementation code before the distribution model is chosen.

Before integrating SimpleX implementation code, choose and obtain legal review for one of:

1. an AGPL-compatible/open-source product;
2. a commercial licence or other arrangement with the relevant upstream rights holders, if available;
3. an independently implemented protocol-compatible client and independently operated infrastructure, developed without copying protected implementation code.

This is an engineering gate as well as a legal one. The `secure-messaging` boundary will be kept independent so the rest of the application is not coupled to a licensing decision.

## Research finding (2026-09-04, not a legal decision)

Confirmed via the upstream repository: `simplex-chat/simplex-chat` is licensed under
**AGPLv3** ([LICENSE](https://github.com/simplex-chat/simplex-chat/blob/stable/LICENSE),
[repository](https://github.com/simplex-chat/simplex-chat)). Practical consequences of that
license, as generally understood for AGPLv3 (this is not legal advice; get real legal review
before acting on it):

- linking or otherwise incorporating SimpleX's Rust implementation code directly into this
  repository's binaries would place the combined work under AGPLv3 obligations for that
  combined work;
- the Affero clause specifically extends "distribution" to include operating the software (or
  a modified version of it) as a network service - running SimpleX-derived server
  infrastructure that users connect to over a network counts as triggering the copyleft
  obligation, not just shipping binaries;
- this repository currently has **no `LICENSE` file and no chosen distribution license of its
  own**. Whether option 1 (ship Secure itself under AGPLv3-compatible terms), option 2 (seek a
  commercial/alternate arrangement with SimpleX's rights holders), or option 3 (a clean-room,
  independently implemented protocol-compatible client, developed without reading or copying
  SimpleX's protected implementation code) is viable depends entirely on what license/business
  model Secure itself is meant to ship under - a decision this document cannot make on the
  project owner's behalf.

No SimpleX implementation code has been imported, linked, or read for reference anywhere in
this repository. This finding does not resolve the gate; it exists so the actual decision, when
made, is made against confirmed facts rather than assumptions.
