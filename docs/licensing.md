# Messaging Integration Licensing Gate

**Status: resolved (2026-09-04).** This document previously described the gate as open. It is
recorded below for its own history, followed by the decision that closes it.

## Decision

Secure ships as an **AGPLv3 open-source client**, monetized through a **commercial
hosted-services layer**, not through the client itself:

- Secure client: free and AGPLv3;
- self-hosting: supported;
- managed Secure relay/network service: paid;
- higher-capacity/premium relay service: paid;
- business/team deployments: paid;
- hosted enterprise/private infrastructure: paid;
- support/managed deployment: paid;
- no advertising, no user-data monetization.

Because the client itself ships AGPLv3, option 1 from the original gate (an AGPL-compatible
product) is the path taken: SimpleX's AGPLv3-licensed implementation code may be integrated
directly into `secure-messaging` where technically appropriate, under the same license.
Options 2 (commercial arrangement with SimpleX's rights holders) and 3 (clean-room
protocol-compatible reimplementation) are no longer necessary given this business model, and
are not being pursued.

This is a business/licensing decision made by the project owner, not a legal opinion; it does
not replace getting real legal review of the resulting distribution before a public release,
particularly around correctly fulfilling AGPLv3's source-availability and network-use
obligations for both the client and any hosted relay/service infrastructure Secure operates.

## Engineering consequence: the adapter boundary is not optional just because linking is now allowed

Being licensed to link SimpleX's implementation code directly is not the same as it being good
architecture to do so throughout the codebase. `secure-messaging` remains the **only** crate
permitted to depend on SimpleX-derived code or types. Every other crate (`secure-core`,
`secure-crypto`, `secure-storage`, `secure-transport`, the Tauri host, the UI) talks to
`secure-messaging` through a protocol-neutral adapter interface and never sees a SimpleX type
directly. The reasons for this are unchanged by the licensing decision:

- the project may want to replace or evolve the messaging substrate later without that decision
  rippling through the rest of the application;
- keeping the boundary narrow keeps the AGPLv3 surface area of "code that actually links
  SimpleX" auditable and small, which matters for correctly fulfilling AGPLv3 obligations even
  though the whole client is AGPLv3 - it is still worth knowing precisely what came from
  upstream versus what Secure wrote;
- it is the same engineering discipline already applied to Tor (`secure-transport` is the only
  crate that touches `arti-client`) and to the vault (`secure-storage` is the only crate that
  touches `rusqlite`/SQLCipher).

## Original gate text (superseded, kept for history)

> The architecture prefers a SimpleX-style asynchronous relay protocol, but the repository must
> not silently absorb upstream implementation code before the distribution model is chosen.
>
> Before integrating SimpleX implementation code, choose and obtain legal review for one of:
>
> 1. an AGPL-compatible/open-source product;
> 2. a commercial licence or other arrangement with the relevant upstream rights holders, if
>    available;
> 3. an independently implemented protocol-compatible client and independently operated
>    infrastructure, developed without copying protected implementation code.

## Research finding (2026-09-04, informed the decision above)

Confirmed via the upstream repository: `simplex-chat/simplex-chat` is licensed under
**AGPLv3** ([LICENSE](https://github.com/simplex-chat/simplex-chat/blob/stable/LICENSE),
[repository](https://github.com/simplex-chat/simplex-chat)). Practical consequences of that
license, as generally understood for AGPLv3 (this is not legal advice):

- linking or otherwise incorporating SimpleX's implementation code directly into this
  repository's binaries places the combined work under AGPLv3 obligations for that combined
  work - which is exactly why Secure now ships AGPLv3 itself, resolving the conflict rather than
  working around it;
- the Affero clause specifically extends "distribution" to include operating the software (or a
  modified version of it) as a network service - running SimpleX-derived server infrastructure
  that users connect to over a network counts as triggering the copyleft obligation, not just
  shipping binaries. This is directly relevant to the "managed Secure relay/network service"
  paid offering in the business model above: that service's own source must remain available to
  its users under AGPLv3, which the business model already anticipates ("self-hosting:
  supported").
