# PathProof

PathProof is an AWS posture scanner and a small, offline experiment in proving a fix. The fastest demonstration reads one harmless test file twice. The anonymous request succeeds before a one-statement fix and receives HTTP 403 afterward. The authorized analyst reads the same file successfully both times.

## Setup once, before the demo

Extract the archive and open a terminal in the folder containing bootstrap.py. Install Python 3.11 with pip and venv available. Setup downloads the pinned direct dependencies. The prepared environment runs the lab offline. The archive also includes a self-contained HTML report and a recording.

**Windows PowerShell**

```powershell
py -3.11 bootstrap.py
.\.venv\Scripts\python.exe -m pytest -q -rs
.\.venv\Scripts\pathproof.exe demo --narrate --out first-demo
Start-Process .\first-demo\report.html
```

**Linux**

```bash
python3.11 bootstrap.py
.venv/bin/python -m pytest -q -rs
.venv/bin/pathproof demo --narrate --out first-demo
xdg-open first-demo/report.html
```

A named output directory must be new. Omit --out for a unique run directory. The commands below assume the environment is active. Use `source .venv/bin/activate` in Bash or `.\.venv\Scripts\Activate.ps1` in PowerShell. You can also use the full executable paths above.

## Live teacher exercise

```text
pathproof lab seed
pathproof lab break T1
pathproof scan --out broken
pathproof replay T1
pathproof fix T1 --preview
pathproof fix T1 --out repaired
pathproof replay T1
pathproof selftest
```

A freshly seeded lab closes the five teaching scenarios. Two posture checks, S301 and S302, deliberately remain failed because the fixture permits policy-based sharing. T1 removes a grant to one object. Its success criterion is the repeated read experiment.

The preview shows the exact field and old/new values. Open repaired/report.html to see the identical plan hash, before/after graphs, HTTP results, digests and business assertions. The report retains both snapshots. A second fix reports already_fixed. lab fix T1 toggles the fixture directly for rehearsals. The top-level fix command measures the change before committing it. Use --lab after a subcommand to select another state file, e.g. pathproof lab seed --lab second-lab.json. A seed never overwrites an existing lab.

| Command | What to expect |
|---|---|
| pathproof demo --narrate | Five scenario evaluations, a before/after report and three business assertions per evaluation. |
| pathproof demo --narrate --backend moto | The same loopback gate with Moto server mode storing the planted object. |
| pathproof scan --snapshot examples/broken.json --severity HIGH --mutelist examples/mute.yaml | JSON retains all findings. CSV and HTML show unmuted High and Critical findings. The compliance subset uses all results. |
| pathproof replay T1 --snapshot examples/broken.json | Pure offline interpretation gives THEORETICAL. It opens no socket. |
| pathproof replay T1 --snapshot examples/broken.json --rehydrate | Rebuild the registered classroom state locally, then try the identical unsigned canary request. |
| pathproof scan --snapshot examples/fixed.json | Fresh reports from a saved inventory after all five fixes. |
| pathproof conformance | Evaluate four packaged policy cases locally. AWS comparisons are skipped by default. |
| pathproof selftest --json | Per-check confusion counts, precision, recall, coverage and abstentions. |
| pathproof demo --risk examples/risk.yaml | Use a different explicit impact, ease or detection multiplier. |

The default demo uses an in-process owned HTTP gate and memory storage. The analyst sends a run-specific local bearer token. Anonymous requests send no identity. Moto mode stores the object privately behind the gate using dummy AWS credentials. Access decisions, simulated identities and lab mutations belong to PathProof. No real AWS account is needed for either backend.

## Expected narrated run

```text
T1 PROVEN -> BLOCKED | verified
T5 present -> absent | verified
T2 THEORETICAL -> BLOCKED | verified
T3 THEORETICAL -> BLOCKED | verified
T4 THEORETICAL -> absent | verified
```

Narration appears between these lines. T5 runs while two other modeled routes are still present, so its before/after graph retains the routes and changes their scores. The score is impact × lowest ease on the path × logging multiplier. Inspect the range when coverage is unknown.

## Optional AWS inspection

Use your own authorized commercial AWS account and read-only SDK profile. Do not put passwords, session tokens or access keys into arguments or files. IAM is global. S3 bucket locations are filtered to the selected regions. EC2, CloudTrail, KMS and RDS are collected per region. All inventory operations are read-only. A read failure produces missing facts and coverage rows.

```text
pathproof collect --regions us-east-1 us-west-2 --out my-inventory.json
pathproof scan --snapshot my-inventory.json --out account-report
pathproof scan --aws --regions us-east-1 --out direct-scan
```

The profile needs STS GetCallerIdentity and the relevant IAM, S3, S3Control, EC2, CloudTrail, KMS and RDS list/get/describe calls used in pathproof/providers. Tagged students use PathProofLowPrivilege=true and bucket/database goals use PathProofCrownJewel=true. An IAM role trust check treats the tagged students as excluded principals for this classroom rule. See docs/limitations.md before applying the tagging convention to another account. A new collection is required to learn about subsequent changes. Report export and offline replay make no AWS calls.

**Passive simulation** evaluates one exact object-read permission. Replace both example ARNs with authorized values. The command does not read the real object. POLICY-VERIFIED is reserved for the real simulator's applicable allow decision.

```text
pathproof replay T1 --aws-principal arn:aws:iam::111111111111:user/reader --object-arn arn:aws:s3:::your-bucket/canary.txt
pathproof conformance --aws-principal arn:aws:iam::111111111111:user/empty-comparison
```

Conformance uses a separate pre-existing empty IAM user in your sandbox. The calling identity needs iam:GetUser, iam:ListUserPolicies, iam:ListAttachedUserPolicies, iam:ListGroupsForUser and iam:SimulatePrincipalPolicy. The program checks the subject and submits synthetic policy inputs only to the simulator. No policy is attached. The unknown-condition case is excluded from the agreement denominator. The optional integration test runs only when PATHPROOF_CONFORMANCE_ARN is set. Unset it before the offline presentation.

## Files to read first

| File or folder | Purpose |
|---|---|
| pathproof/cli.py | Command parsing, explicit online modes and exit codes |
| pathproof/providers/ | Six AWS service collectors and shared pagination/coverage logic |
| pathproof/checks/ and pathproof/assets/checks/ | Thirty functions with one metadata file per check |
| pathproof/fixtures.py and pathproof/assets/lab.yaml | Classroom principals, canary, patches and business assertions |
| pathproof/assets/techniques/ | Exactly five declarative technique definitions |
| pathproof/analysis.py and pathproof/policy.py | Evidence graph, bounded search, scoring and local policy decisions |
| pathproof/sandbox.py and pathproof/storage.py | Owned loopback request, authorization and object storage |
| pathproof/replay.py | Saved plans, verdicts, proof-of-fix and repeated assertions |
| pathproof/reports.py | Filtering, mutelist, CIS subset and JSON/CSV/HTML output |
| tests/ | Unit, scenario, CLI, optional SDK, Moto, NetworkX and conformance tests |
| docs/ | Glossary, scope, catalogue, architecture, oral questions and scripts |
| demo-fallback/ | Report, replay evidence and recorded terminal run |

The installed project uses NetworkX and embeds the local vis-network asset provided by pyvis when producing HTML. If NetworkX or pyvis is unavailable, the small classroom graph can still be rehearsed with the labelled standard-library enumerator and a static SVG. The report identifies its graph engine. Both modes retain the relationship table. The standalone fallback report works without installing Python.

## Evidence and recovery

A scan exits 0 when it completes, including when it detects findings. Self-test, demo or fix exit 1 on unmet expectations. Configuration and operational errors exit 2. A file lock serializes lab mutations. After an interrupted process, check that no PathProof process owns the lab before removing its orphaned .lock file. Each committed state write uses atomic replacement. If an output folder contains files from an interrupted run, preserve it and choose a new output folder.

Version 2 stores a canonical inventory hash. The capture time is outside this hash. Fixtures use a fixed teaching timestamp. The scanner can import a valid Week 1 classroom snapshot for S302; the old file has insufficient data for active rehydration. See docs/verification.md for what was actually tested on the build machine.
