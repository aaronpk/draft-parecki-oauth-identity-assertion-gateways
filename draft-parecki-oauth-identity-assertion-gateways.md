---
title: "Identity Assertion Authorization Grant for Gateways"
abbrev: "ID-JAG for Gateways"
category: std
docname: draft-parecki-oauth-identity-assertion-gateways-latest
submissiontype: IETF
number:
date: 2026-09-02
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - oauth
 - cross app access
 - gateway
 - token exchange
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"

author:
 -
    fullname: "Aaron Parecki"
    organization: "Okta"
    email: "aaron@parecki.com"

normative:
  RFC2119:
  RFC6749:
  RFC7523:
  RFC8174:
  RFC8693:
  RFC8707:
  I-D.ietf-oauth-identity-assertion-authz-grant:

informative:
  RFC9728:

--- abstract

The Identity Assertion Authorization Grant {{I-D.ietf-oauth-identity-assertion-authz-grant}}
enables a client to obtain an access token for a resource in another application, using an
identity assertion issued by a common Identity Provider. That flow assumes the client
communicates with the Resource Server directly.

This specification extends that grant to deployments in which a gateway sits between the client
and the Resource Server. It defines a chained token exchange, in which a gateway presents an
Identity Assertion Authorization Grant that was issued to it as the subject token, and receives
in return an Identity Assertion Authorization Grant for a Resource Authorization Server behind
it. It additionally defines an optional token exchange that allows a gateway's authorization
server and resource server to be operated as separate deployments.

Neither the client nor the Resource Authorization Server is affected by this extension.

--- middle

# Introduction

{{I-D.ietf-oauth-identity-assertion-authz-grant}} defines the Identity Assertion Authorization
Grant, referred to in this document as an ID-JAG. A client obtains an ID-JAG from an Identity
Provider by presenting an identity assertion, and redeems that ID-JAG at a Resource
Authorization Server to obtain an access token for a Resource Server.

In enterprise deployments, a gateway is frequently interposed between the client and the
Resource Server, in order to apply policy, logging, filtering, or aggregation to requests that
would otherwise reach the Resource Server directly. The motivating case for this document is a
gateway fronting several Model Context Protocol servers, but nothing in this specification is
specific to that protocol.

Such a gateway is an OAuth Resource Server to the client and an OAuth client to the Resource
Authorization Server. It therefore terminates the client's access token and must independently
obtain an access token of its own for the Resource Server, on behalf of the same subject.

An access token issued by the gateway cannot serve as the subject token in an exchange at the
Identity Provider, because the Identity Provider cannot validate a token it did not issue. The
ID-JAG that the client redeemed at the gateway can, because the Identity Provider issued it.
This specification defines how a gateway presents that assertion to obtain a further assertion
for a resource behind it.

## Conventions and Terminology

{::boilerplate bcp14-tagged}

This document uses the terms "Identity Provider", "Client", "Resource Authorization Server",
"Resource Server", and "identity assertion" as defined in
{{I-D.ietf-oauth-identity-assertion-authz-grant}}, and additionally defines:

ID-JAG:
: An Identity Assertion Authorization Grant, as issued by an Identity Provider according to
  {{I-D.ietf-oauth-identity-assertion-authz-grant}}. Its `typ` header is `oauth-id-jag+jwt`.

Gateway:
: An entity that accepts requests from a Client and forwards them to one or more Resource
  Servers, obtaining an access token for each Resource Server itself. A Gateway comprises a
  Gateway Authorization Server and a Gateway Resource Server, which MAY be the same deployment.

Gateway Authorization Server:
: The authorization server component of a Gateway. It is the Resource Authorization Server from
  the Client's point of view: it accepts an ID-JAG whose audience identifies it, and issues the
  access token that the Client presents to the Gateway Resource Server.

Gateway Resource Server:
: The resource server component of a Gateway. It validates the access token issued by the
  Gateway Authorization Server and forwards the request to a Resource Server, presenting an
  access token obtained for that Resource Server.

Upstream:
: The Resource Authorization Server and Resource Server that a Gateway obtains an access token
  for, as distinct from the Gateway itself.


# Protocol Overview

The Client interacts with the Gateway exactly as
{{I-D.ietf-oauth-identity-assertion-authz-grant}} already specifies: it discovers, for example
through the protected resource metadata of {{RFC9728}}, that the Gateway's protected resource is
served by the Gateway Authorization Server, obtains an ID-JAG whose audience identifies the
Gateway Authorization Server, and redeems it there for an access token. The Resource Authorization Server likewise receives an ordinary ID-JAG grant from a
registered client. Neither role is aware that a Gateway is involved.

~~~ ascii-art
                            +----------------+
                            |    Identity    |
                            |    Provider    |
                            +----------------+
                              ^     ^      :
                    (1) ID-JAG|     |(2)   : SSO trust
                       request|     |NEW   : relationship
                              |     |      :
  +--------+                  |     |      :     +----------------+
  | Client |------------------+     |      :.....|   Resource     |
  +--------+                        |            | Authorization  |
    |    |                          |            |     Server     |
    |    |  (3) ID-JAG grant  +-----+------+     +----------------+
    |    +------------------->|  Gateway   |          ^
    |                         |   Authz    |----------+
    |                         |   Server   |  (4) ID-JAG grant
    |                         +------------+
    |                            ^
    | (5) resource request       | (6) NEW, OPTIONAL
    v                            |
  +------------------+           |
  | Gateway Resource |-----------+
  |      Server      |
  +------------------+
    |
    | (7) resource request
    v
  +------------------+
  | Resource Server  |
  +------------------+
~~~
{: #fig-overview title="Entities and their interactions"}

Interactions (1), (3), (4), (5) and (7) are unchanged from
{{I-D.ietf-oauth-identity-assertion-authz-grant}} and are not defined here. This specification
defines:

(2):
: The Chained Identity Assertion Request ({{chained-request}}), in which the Gateway
  Authorization Server presents the ID-JAG it received in (3) as the subject token, and obtains
  an ID-JAG whose audience is the Resource Authorization Server. This is REQUIRED.

(6):
: The Upstream Token Request ({{upstream-request}}), in which the Gateway Resource Server
  obtains an upstream access token from the Gateway Authorization Server. This is OPTIONAL, and
  is only necessary when the two components are separate deployments.


# Chained Identity Assertion Request {#chained-request}

The Gateway Authorization Server obtains an ID-JAG for an upstream Resource Authorization Server
by making a token exchange request {{RFC8693}} to the Identity Provider, presenting an ID-JAG
that the Identity Provider previously issued for the Gateway Authorization Server itself.

## Request

The Gateway Authorization Server makes a request to the Identity Provider's token endpoint using
the `urn:ietf:params:oauth:grant-type:token-exchange` grant type, with the following parameters:

`grant_type`:
: REQUIRED. Value MUST be `urn:ietf:params:oauth:grant-type:token-exchange`.

`requested_token_type`:
: REQUIRED. Value MUST be `urn:ietf:params:oauth:token-type:id-jag`.

`subject_token`:
: REQUIRED. The ID-JAG that was issued by this Identity Provider with an `aud` claim identifying
  the requesting Gateway Authorization Server.

`subject_token_type`:
: REQUIRED. Value MUST be `urn:ietf:params:oauth:token-type:id-jag`.

`audience`:
: REQUIRED. The issuer identifier of the upstream Resource Authorization Server for which the
  new ID-JAG is requested.

`resource`:
: OPTIONAL. The resource indicator of the upstream Resource Server, as defined in {{RFC8707}}.

`scope`:
: OPTIONAL. The space-separated list of scopes requested at the upstream Resource Server.

`authorization_details`:
: OPTIONAL. As defined in {{I-D.ietf-oauth-identity-assertion-authz-grant}}.

The Gateway Authorization Server MUST authenticate to the Identity Provider's token endpoint
using a client identity registered with the Identity Provider for that purpose. The `actor_token`
parameter of {{RFC8693}} is not used; the acting party is established by client authentication.

The following is a non-normative example. Line breaks are for display purposes only.

~~~ http-message
POST /oauth2/token HTTP/1.1
Host: idp.example
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid-jag
&subject_token=eyJ0eXAiOiJvYXV0aC1pZC1qYWcrand0Iiwi...
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid-jag
&audience=https%3A%2F%2Fchat.example
&resource=https%3A%2F%2Fchat.example%2Fmcp
&scope=mcp
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
   client-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIsImtpZCI6ImdhdGV3...
~~~

## Identity Provider Processing

On receiving a request as described in the preceding section, the Identity Provider MUST:

1. Authenticate the client. The authenticated client is the acting party for the purposes of
   this exchange.

2. Validate the `subject_token` as an ID-JAG that it issued, including its signature, its `typ`
   header value of `oauth-id-jag+jwt`, and its expiration.

3. Verify that the `aud` claim of the `subject_token` identifies an authorization server
   operated by the authenticated client. An Identity Provider MUST NOT accept an assertion whose
   audience identifies any other party. This is what distinguishes a Gateway redeeming an
   assertion issued to it from an unrelated party replaying an assertion it observed.

4. Verify, according to policy configured by the Identity Provider's administrator, that the
   authenticated client is permitted to act as a Gateway for the requested `audience`, for the
   subject identified by the `subject_token`, and for the client identified by the `client_id`
   claim of the `subject_token`.

5. Verify that the requested `audience` does not identify an authorization server operated by
   the authenticated client, so that an assertion cannot be chained to itself.

6. Unless the Identity Provider's policy explicitly permits a longer chain, reject a
   `subject_token` that already contains an `act` claim. See {{chain-depth}}.

If any of these steps fails, the Identity Provider MUST respond with an error as described in
{{errors}}.

An Identity Provider MUST NOT treat an ID-JAG presented as a `subject_token` as single use. The
same assertion MAY be presented more than once within its validity period, in order to obtain
grants for different audiences. A Gateway fronting several upstreams does not know in advance
which of them a given request will require, and requiring it to obtain grants for all of them at
once would force it to request authorization it may never use.

## Response

The Identity Provider responds as described in {{RFC8693}} and
{{I-D.ietf-oauth-identity-assertion-authz-grant}}. The `issued_token_type` MUST be
`urn:ietf:params:oauth:token-type:id-jag`, the `token_type` MUST be `N_A`, and `access_token`
MUST contain the issued ID-JAG.

The issued ID-JAG MUST contain the claims required by
{{I-D.ietf-oauth-identity-assertion-authz-grant}}, with the following additional requirements:

`sub`:
: MUST identify the same subject as the `sub` claim of the `subject_token`. A Gateway cannot
  cause an assertion to be issued for a different subject than the one it was given.

`aud`:
: MUST identify the requested `audience`.

`client_id`:
: MUST be the identifier of the Gateway at the upstream Resource Authorization Server. The
  Gateway, not the original Client, is the client that will present this grant.

`act`:
: The Identity Provider SHOULD include an `act` claim, as defined in {{RFC8693}}, identifying
  the Gateway as the acting party. Because `act` is OPTIONAL in
  {{I-D.ietf-oauth-identity-assertion-authz-grant}}, a Resource Authorization Server that does
  not implement this specification will ignore it, so including it does not affect
  interoperability. The Identity Provider MAY nest within it a further `act` claim identifying
  the original Client, to express the full delegation chain.

The Identity Provider MUST NOT issue a refresh token in response to this request. A Gateway that
held a refresh token could obtain assertions for a subject with no Client driving it, which is
outside the delegation this grant expresses.

The issued ID-JAG is redeemed at the upstream Resource Authorization Server exactly as described
in {{I-D.ietf-oauth-identity-assertion-authz-grant}}, using the
`urn:ietf:params:oauth:grant-type:jwt-bearer` grant type of {{RFC7523}}. That interaction is
unchanged and is not defined here.

The following is a non-normative example response.

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
  "access_token": "eyJ0eXAiOiJvYXV0aC1pZC1qYWcrand0Iiwi...",
  "token_type": "N_A",
  "expires_in": 300,
  "scope": "mcp"
}
~~~

## Error Responses {#errors}

Error responses are as defined in {{RFC8693}} and {{RFC6749}}. In particular:

`invalid_grant`:
: The `subject_token` is not a valid ID-JAG, has expired, was not issued by this Identity
  Provider, or its `aud` claim does not identify an authorization server operated by the
  authenticated client.

`invalid_target`:
: The requested `audience` or `resource` is unknown, or the authenticated client is not
  permitted to act as a Gateway for it.

`invalid_client`:
: Client authentication failed.

An Identity Provider SHOULD NOT distinguish, in the error it returns, between an `audience` that
does not exist and one the client is not permitted to front, so that the error response cannot be
used to enumerate the resources of an organization.


# Retaining the Identity Assertion {#retention}

In order to make a Chained Identity Assertion Request at the time a resource request arrives, a
Gateway Authorization Server needs the assertion it was given. Therefore:

* A Gateway Authorization Server MUST associate the ID-JAG it received from the Client with the
  access token it issues in exchange, so that the assertion can be used to satisfy later
  requests made with that access token.

* A Gateway Authorization Server MUST NOT issue an access token whose expiration is later than
  the expiration of the ID-JAG it was presented, unless it has already obtained the upstream
  access tokens that the access token will be used to reach. An access token that outlives the
  assertion behind it cannot be honored.

* A Gateway Authorization Server SHOULD reject an ID-JAG that it has already redeemed, so that
  the Client presents a freshly issued assertion. {{I-D.ietf-oauth-identity-assertion-authz-grant}}
  permits a Client to replay an ID-JAG to obtain a new access token, and an assertion that has
  expired in the interim cannot be used as a subject token.

A Gateway Authorization Server MUST NOT retain the ID-JAG beyond the lifetime of the access
tokens issued in exchange for it.


# Upstream Token Request {#upstream-request}

This section is OPTIONAL to implement. It is required only when the Gateway Authorization Server
and the Gateway Resource Server are separate deployments.

Whether an authorization server is operated separately from its resource server is a private
matter between those two components, and MUST NOT change the behavior of any other party. A
Gateway Resource Server therefore obtains an upstream access token from its own authorization
server using a token exchange request {{RFC8693}}, which collapses to an internal operation when
the two components are a single deployment.

## Request

`grant_type`:
: REQUIRED. Value MUST be `urn:ietf:params:oauth:grant-type:token-exchange`.

`subject_token`:
: REQUIRED. The access token that the Client presented to the Gateway Resource Server.

`subject_token_type`:
: REQUIRED. Value MUST be `urn:ietf:params:oauth:token-type:access_token`.

`audience`:
: REQUIRED. The issuer identifier of the upstream Resource Authorization Server.

`resource`:
: OPTIONAL. The resource indicator of the upstream Resource Server {{RFC8707}}.

`scope`:
: OPTIONAL. The scopes requested at the upstream Resource Server.

The Gateway Resource Server MUST authenticate to the Gateway Authorization Server's token
endpoint.

## Processing

The Gateway Authorization Server MUST:

1. Authenticate the Gateway Resource Server, and verify it is permitted to request upstream
   tokens.

2. Verify that the `subject_token` is an access token it issued and that has not expired or been
   revoked.

3. Locate the ID-JAG associated with that access token, as described in {{retention}}.

4. Perform the Chained Identity Assertion Request of {{chained-request}} for the requested
   `audience`, and redeem the resulting ID-JAG at the upstream Resource Authorization Server.

## Response

The response is an OAuth 2.0 token response containing the upstream access token, with
`issued_token_type` set to `urn:ietf:params:oauth:token-type:access_token`. The
`expires_in` value SHOULD be included so that the Gateway Resource Server can cache the token
for its remaining lifetime.

The Gateway Authorization Server MUST NOT return a refresh token, and MUST NOT return an access
token for an `audience` other than the one requested.


# Security Considerations

## Restriction to assertions issued to the Gateway

The check in {{chained-request}} that the `subject_token`'s `aud` identifies an authorization
server operated by the authenticated client is essential. Without it, any party that obtained an
ID-JAG — including a Resource Authorization Server that legitimately received one — could present
it to obtain grants for unrelated audiences. Combined with the policy check, the Identity
Provider remains the only party that decides which resources a Gateway may reach.

## Chain depth {#chain-depth}

An Identity Provider that accepts an assertion already containing an `act` claim permits a
Gateway behind a Gateway. Each additional hop adds a party that must be trusted with the
subject's authority, and the accumulated `act` chain is the only record of it. Identity Providers
SHOULD therefore permit a single hop by default, as required in {{chained-request}}, and treat
longer chains as explicit configuration.

## Aggregation of authority at the Gateway

A Gateway obtains access tokens for every upstream it fronts, for every subject currently using
it. Compromise of a Gateway therefore exposes those tokens. This is inherent to interposing a
gateway and is not introduced by this specification, but two properties limit it: the Gateway
holds no credential from which further authority can be derived once its retained assertions
expire, and the Identity Provider's policy bounds the set of upstreams reachable at all.

Deployments SHOULD prefer assertions and access tokens with short lifetimes over long-lived ones,
since the Client can obtain a fresh assertion without user interaction.

## No refresh tokens

Neither the Identity Provider ({{chained-request}}) nor the Gateway Authorization Server
({{upstream-request}}) issues a refresh token. A Gateway holding a refresh token could act for a
subject with no Client driving it. That is a different delegation from the one this grant
expresses, and it would place a long-lived credential for every subject at the Gateway.

## Subject binding of cached tokens

A Gateway Resource Server that caches upstream access tokens, or that maintains protocol state
such as session identifiers on behalf of a Client, MUST bind each cache entry to the subject and
issuer of the access token that produced it, and MUST verify that binding on every request. A
cache keyed only by an identifier supplied by the Client would allow one subject to reach
another's upstream tokens or session state.

## Audience of tokens issued by the Gateway

A Gateway Authorization Server SHOULD issue an access token whose audience identifies the
specific protected resource the Client requested, rather than the Gateway as a whole, so that a
token obtained for one upstream cannot be presented to reach another.

## Client authentication at the Identity Provider

The `actor_token` parameter of {{RFC8693}} is not used by this specification; the acting party is
established by client authentication. Identity Providers SHOULD require an authentication method
that does not rely on a shared secret, so that the acting party cannot be impersonated by a party
that has observed a credential in transit.


# IANA Considerations

This document requires no new registrations.

The value `urn:ietf:params:oauth:token-type:id-jag`, registered by
{{I-D.ietf-oauth-identity-assertion-authz-grant}} in the "OAuth URI" registry, is used by this
specification as a `subject_token_type` in addition to its existing use as a
`requested_token_type` and `issued_token_type`. That use requires no additional registration.


--- back

# Design Rationale

This appendix is non-normative. It records the reasoning that produced the flow above, for
readers who need to understand why it is shaped this way.

## Burden of implementation

The design of {{I-D.ietf-oauth-identity-assertion-authz-grant}} distributes implementation effort
according to motivation. The parties with the least inherent reason to adopt it have the least to
do: a Resource Authorization Server adds one grant type and changes neither its token format nor
its resource servers, while the Identity Provider, whose customers are the ones asking for the
capability, does the most work. That distribution is a substantial part of why the grant was
adopted quickly, and an extension that disturbed it would not see the same adoption.

Gateways do not change who is motivated. A Gateway vendor sells to the same customer as the
Identity Provider and is highly motivated. Clients and Resource Authorization Servers gain
nothing from a Gateway's presence — from their point of view a Gateway is transparent, or ought to
be. So the requirement this specification holds itself to is that no change fall on either of
them:

* A Client implementing the base grant interoperates with a Gateway with no changes. It discovers
  a protected resource, obtains an assertion for the authorization server it was told about, and
  redeems it. That the resulting access token is honored by a Gateway rather than by the Resource
  Server it ultimately reaches is not visible to it.

* A Resource Authorization Server implementing the base grant interoperates with a Gateway with
  no changes. It receives an ID-JAG from a registered client and validates it exactly as before.
  The `act` claim this specification recommends is OPTIONAL in the base grant and is ignored by
  an implementation that does not look for it.

Everything new is therefore confined to the Identity Provider and the Gateway: one new subject
token type at the Identity Provider, and one internal exchange within the Gateway.

## Why the assertion, and not an access token

The Gateway must present something to the Identity Provider that identifies the subject and that
the Identity Provider can verify. It holds two candidates: the access token it issued to the
Client, and the ID-JAG the Client redeemed.

An access token issued by the Gateway is not verifiable by the Identity Provider. Making it
verifiable would require the Identity Provider either to trust keys published by the Gateway, or
to call the Gateway to introspect the token. Both make the Identity Provider dependent on a
Gateway's assertions about who a subject is, inverting the direction of trust that the rest of
the flow rests on, and both give a Gateway the standing capability to obtain assertions for any
subject at any time.

The ID-JAG requires none of that. The Identity Provider issued it, so it can verify it, and its
`aud` claim proves which party it was issued to.

## Why the Gateway holds nothing durable

The only long-lived credential in this flow is the Client's, at the Identity Provider, which is
where the base grant already places it. The Gateway holds a short-lived assertion for the
lifetime of one access token, and access tokens it can obtain again. Discarding all of a
Gateway's stored state costs it nothing beyond the work of rebuilding it on the next request.

This bounds what a compromised Gateway yields to the sessions active at the time. The alternative
— giving the Gateway a durable per-subject credential — would let it obtain assertions
indefinitely, and would require it to protect a credential store rather than a cache.

## Absence of the user is the Client's problem, already solved

A Gateway does not need to act while the user is away, because the Client's own request for an
assertion does not require the user either: {{I-D.ietf-oauth-identity-assertion-authz-grant}}
permits an Identity-Provider-issued refresh token as the subject token precisely because an
assertion is usually requested long after the user's identity token expired.

So a Client can obtain a fresh assertion at any time, and a Gateway consequently receives a
fresh, verifiable assertion at any time. The freshness constraint in {{retention}} is not about
whether a user is present; it is only about the interval between one redemption and the next.

## Why the Gateway has no independent authority

A Gateway acts only because a Client asked it to. It cannot initiate a request, and it cannot act
for a subject whose Client is not driving it. This is what distinguishes a Gateway from a Client
in its own right, and it is why neither exchange defined here returns a refresh token.

## Separability of the Gateway's components

Whether an authorization server is operated separately from its resource server is conventionally
private between those two components: it is settled by deployment, and the rest of the protocol
does not change either way. Preserving that property is what makes {{upstream-request}} a token
exchange rather than a private interface.

It also determines where each responsibility sits. The Gateway Authorization Server is the only
component that communicates with the Identity Provider, and it holds only the grant it was
presented. The Gateway Resource Server communicates with neither the Identity Provider nor any
upstream authorization server; it validates a token and exchanges it for another, which is
ordinary behavior for a resource server that makes onward calls. Nothing upstream-specific has to
be configured in the authorization server beyond an audience it is asked for.

The alternative — having the Gateway Authorization Server obtain upstream tokens for every
configured upstream at the moment of redemption, and deliver them to the resource server — would
place upstream credentials in the component that has no use for them, and would couple the two
components through token lifetimes and the list of upstreams.

## Reuse of the assertion

A Gateway fronting several upstreams does not know, when it issues an access token, which
upstreams a Client will reach through it. Obtaining grants for all of them at redemption would
mean requesting authorization that is never exercised, and would make the access token's lifetime
depend on upstreams the Client never asks for. Permitting the assertion to be presented more than
once within its validity period is what allows a Gateway to obtain each grant on first use
instead.


# Acknowledgments
{:numbered="false"}

TODO
