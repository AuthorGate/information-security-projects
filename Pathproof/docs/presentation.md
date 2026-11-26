# Live demonstration and oral defence

## 90 seconds

| Time | Action | Say |
|---|---|---|
| 0–15 s | Show examples/broken.json with the T1 bucket statement highlighted. | “The planted file is harmless. The question is who can read it after one policy change.” |
| 15–35 s | Run pathproof demo --narrate. | “The anonymous request ran against the local gate. We saved the status and the digest.” |
| 35–60 s | Open the printed report. Expand T1 and its request evidence. | “Both measurements use the same plan hash. The response changed from 200 to 403.” |
| 60–80 s | Point to reader_can_read_canary and the role/metadata results. | “The intended reader got 200 both times. Trust and metadata conclusions have different evidence.” |
| 80–90 s | Show one self-test row and the documented scope. | “The result describes this fixture and these assertions. Here is how a missed bad case lowers recall.” |

## Five minutes

| Time | Action |
|---|---|
| 0:00–0:45 | Explain one input resource, coverage row and check metadata file. Disconnect Wi-Fi. |
| 0:45–1:30 | Seed a new lab. Let the teacher choose T1, run lab break T1, then scan. Identify the failing rule. |
| 1:30–2:30 | Run replay T1, preview the patch, then run fix T1. Show both raw HTTP results and authorized reads. |
| 2:30–3:30 | Open the demo report and compare T2 and T4 with T1. Expand T5 and compare the same path's score before and after. |
| 3:30–4:15 | Show the static snapshot replay and optional local rehydration. Explain the guard and absent secret values. |
| 4:15–5:00 | Run selftest and conformance. State what the small truth set can establish. Invite a change to a rule and repeat the scan. |

If the environment fails during class, open demo-fallback/report.html directly. Use demo-fallback/recorded-run.mp4 to show the captured run. The recording displays actual command output paced for reading. Its graph engine and backend are recorded in the report.

## Ten-slide outline

1. The two readers and the testable question.
2. A snapshot, its collection scope and a single finding.
3. Thirty checks, six services and a missing-observation example.
4. A labeled path and a crown jewel with no established route.
5. Five techniques and the status of their evidence.
6. One saved canary plan, a digest and an HTTP response.
7. The one-statement patch and the legitimate reader's result.
8. Fixture precision, recall and abstention.
9. Prowler comparison and limitations of the classroom experiment.
10. Live teacher challenge and reproducible evidence files.

## Comparison with Prowler

| Capability | Prowler evidence | What to claim for PathProof |
|---|---|---|
| AWS posture and compliance | The open-source project documents hundreds of checks, multiple providers, and versioned frameworks. | Thirty educational AWS controls, conservative unknowns and small fixture-based metrics. |
| Attack Paths | The project documents an AWS API-worker pipeline combining findings with Cartography and using a temporary Neo4j database during ingestion. | A small fixture graph in memory with evidence-scoped relations, tunable scores and portable snapshots. |
| Fixers and re-evaluation | CLI fixers are documented, as are cloud remediation workflows. | One isolated local patch, identical canary plan, before/after graph, and a repeated authorized read. |
| Editions and novelty | Blanket claims about which features are always paid-only, absence of offline support, or absence of accuracy testing are **unverified**. | Demonstrate this implementation and its specific evidence. Avoid claims of industry-wide novelty. |

Sources: [Prowler OSS repository](https://github.com/prowler-cloud/prowler), [Prowler CLI fixer workshop](https://prowler.com/workshops/defcon-2026), [Prowler compliance documentation](https://docs.prowler.com/user-guide/compliance/tutorials/compliance), [Prowler remediation workflow](https://prowler.com/blog/prowler-autonomous-fixer-guided-remediation-for-cloud-misconfigurations).

## Thirty oral questions

| Question | Answer to defend |
|---|---|
| 1. Isn't this just Prowler Attack Paths? | Prowler already correlates attack paths. My demonstration binds a harmless read, a minimal patch and a repeated authorized read to one saved local experiment. |
| 2. Why not use Neo4j? | The fixture fits in memory and a fresh process rebuilds it cheaply. A persistent graph would be useful for larger historical inventories. |
| 3. Is this legal and safe? | I operate my own teaching fixtures. Real-account use requires the owner's authorization and supports configuration reads and passive simulation only. Specific legal obligations depend on the setting. |
| 4. What can create a false positive in the IAM evaluator? | Missing policy layers, unsupported conditions and differing service semantics. Supported decisions are scoped and missing inputs must remain unknown. |
| 5. What exactly did you prove? | The anonymous reader got the registered bytes from the owned lab under the local gate at the time recorded by the run. |
| 6. Why check the digest? | HTTP success could return an error page or another file. The known digest verifies the object contents. |
| 7. Why repeat the legitimate read? | A broad deny could fix the exposure by breaking everyone's access. The authorized read tests that failure mode. |
| 8. Can Moto validate AWS IAM? | It stores the lab object. PathProof enforces the local teaching rules and discloses that decision source. |
| 9. What makes a patch minimal? | The registered fixture isolates one statement or scalar. The diff shows that only that element changed. |
| 10. Could another path survive the fix? | Yes. Each proof rebuilds the graph. A second grant can keep the canary readable and make verification fail. |
| 11. What happens to the original snapshot? | It is retained alongside the new snapshot. Both can be analyzed again offline. |
| 12. What does the snapshot hash establish? | It identifies canonical inventory bytes. An editor could recompute the hash, so authorship is not established. |
| 13. Does a muted failure improve compliance? | No. Muting only changes the report view. The full findings supply the compliance calculation. |
| 14. Does a missing AWS permission produce PASS? | Failed reads yield unknown facts or coverage findings, with MANUAL status. |
| 15. Does a public IP expose metadata credentials? | It is insufficient. The chain also assumes a reachable vulnerable workload, which the tool never exercises. |
| 16. Did the student actually assume the role? | No. T2 evaluates caller and trust permissions for the declared model; its downstream grant remains modeled. |
| 17. Did T3 escalate privileges? | No. It assesses a permission to manage policy. The simulator or local evaluator receives a question; the identity never gains a privilege. |
| 18. Is a logging gap an attack step? | It changes prioritization. The before/after graph can keep identical edges while risk scores change. |
| 19. Why the lowest ease on a path? | Every required step must be feasible. This explicit heuristic reflects the hardest step, and the configuration exposes the weights. |
| 20. Is the risk score a probability? | No. It ranks this dataset under chosen weights. Unknown detection coverage can produce a range. |
| 21. Why treat an explicit deny specially? | An applicable unconditional deny resolves the supported decision even if another statement could allow it. |
| 22. What does NotAction mean here? | It complements the listed action patterns for the supported action/resource pair being evaluated. Unsupported action/resource families yield UNKNOWN. |
| 23. Why not treat an HTTP 403 as proof of a fix? | The denial must be attributable to the registered gate for the exact request. An unrelated service error stays inconclusive. |
| 24. What is the false-negative rate? | On labeled cases it is FN divided by TP+FN. The fixture count is too small to give a deployment-wide estimate. |
| 25. How can I tell the metrics work? | A regression test deliberately changes one bad decision and one good decision, then verifies the expected changes to recall and precision. |
| 26. Can I run it offline tomorrow? | After setup, yes. Open the same snapshot and run the local demo. The HTML and video fallback also work offline. |
| 27. How are credentials protected? | Evidence is constructed from approved fields. Real SDK credentials, temporary reader tokens, signed headers and object bodies are excluded. |
| 28. How would Azure fit? | Add collectors and provider-specific authorization and scope rules, then reuse the evidence and report interfaces. |
| 29. Why does a database sometimes have no path? | A goal tag defines importance. Only supported evidence creates a relationship, so a goal can remain isolated. |
| 30. What would you improve first? | Add independently curated raw-response fixtures, differential tests for more policy cases, richer scope coverage and a larger labeled accuracy dataset. |
