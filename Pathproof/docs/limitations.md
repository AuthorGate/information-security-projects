# Evidence, boundaries and ethics

**PROVEN means "executed in the owned lab under PathProof's own authorization gate, not evidence about real AWS behaviour".**

| Result | Evidence required |
|---|---|
| PROVEN | An allowed request reached the owned HTTP listener, returned 200, and its body matched the registered canary digest. The evidence records the actor, operation, backend and response. |
| POLICY-VERIFIED | The real AWS IAM simulator returned allowed for the exact named principal, object and action with no missing context. This is a scoped authorization prediction. |
| THEORETICAL | Snapshot facts or the local evaluator support a candidate configuration or relationship. A modeled role transition never receives an executed-access verdict. |
| BLOCKED | The local gate returned 403 with a recognized denial, a required local permission received a definite deny, or the named AWS simulator query was denied. The decision source and control are recorded. |
| No verdict | Missing context, wrong body, unexplained service denial, transport failure, absent modeled prerequisite, or a score-only assessment. |

## IAM subset

The evaluator handles Allow and Deny, lists or strings of action/resource patterns, * and ? wildcards, and NotAction for three supported action/resource pairs. Action matching ignores case. Resource matching preserves case. Trust supports an AWS principal ARN, a list of exact ARNs, or a whole wildcard. Explicit applicable deny takes precedence. A potentially relevant unsupported statement yields UNKNOWN unless a conclusive explicit deny already applies. Policy documents are inputs; the evaluator does not fetch policies or modify identities.

Supported action/resource families are object read, the named role trust decision, and a self policy-management permission query. Conditions, variables, NotResource, NotPrincipal, federated and service principals, account-root delegation, service-specific context, cross-account combinations, organization controls, boundaries, session policies and KMS grants are outside the evaluator. Real effective permissions require more context. AWS simulation can differ from service behavior. [AWS IAM simulation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html)

## What the scanner and graph measure

The collectors preserve selected booleans, identifiers and decision summaries, not raw API responses. Raw secrets, credential IDs, policy documents from real accounts, object contents, database passwords and arbitrary tag values are excluded. Identifiers such as ARNs, regions and resource names remain visible. An inventory is sensitive. Its hash detects edits but provides no signature of authorship.

Real IAM06 looks for a trust-policy match for a tagged low-privilege principal under the documented classroom exclusion convention. IAM07 flags an observed direct inline self-management allow for a tagged user; it cannot certify the absence of grants through other policy layers. S303 inspects the bucket policy for an anonymous grant on the fixed canary key. A bucket could have other ACLs, organization/account settings, access points, other keys, or conditions that change accessibility. Only the local experiment reads an actual object. The EC2 administration checks cover SSH and RDP. CIS labels refer to evidence within a tested subset. No report certifies compliance.

The graph searches from each modeled low-privilege start and Internet to each labeled goal. An isolated database is a legitimate result. The T3 self-edge describes an authority and does not create an imaginary read permission. T2 and T4 carry a separate, scoped role-to-canary observation. T4 would require a workload-level way to reach metadata. No metadata request occurs. T5 checks trail coverage and does not establish that S3 data events were recorded. [CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)

The active scenarios and multi-step route definitions bind to the declared lab aliases. For real AWS inventories the graph shows collected identities/resources and explicit bucket policy observations. It does not enumerate general effective privilege-escalation routes or assert reachability between arbitrary production principals. Access uncertainties remain visible. Snapshot-only replay performs no network calls. Rehydration accepts only an exactly reconstructible classroom fixture and always uses freshly planted local bytes.

## Fixes and accuracy

Minimality means one identified fixture statement or setting was changed. The proof records the complete field before and after. Competing or edited matching statements are refused. A secondary grant can prevent successful repair. The top-level fix leaves live lab state unchanged on unresolved verification. Business assertions cover only the named analyst read, approved trust declaration and expected role attachment. The role-trust assertion is a policy decision, not a live session.

The accuracy dataset has one known-good, one known-bad and one unknown case per check. For 28 controls the self-test starts with recorded-shaped service responses and uses the normal collectors to derive the facts. The trust and self-management checks use local classroom policies to supply known effective decisions. Precision and recall describe these packaged examples, not a representative sample of AWS accounts. A missed known-bad decision reduces recall. An undefined denominator stays null.

## Ethics and scope

Use only authorized inventories and owned lab fixtures. Active requests use the literal 127.0.0.1 address and the port bound by the process, with no user-supplied endpoint, redirects or proxy forwarding. The local reader token is never logged. Treat shared or untrusted multi-user hosts as outside the teaching lab's threat model. The only live-account operations are configuration reads and opt-in permission simulation. The program does not assume roles, change permissions, read real objects or request instance credentials.
