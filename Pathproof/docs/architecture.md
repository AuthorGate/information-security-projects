# Following one result through the program

1. The CLI selects a saved inventory, AWS read-only collector, or owned lab. Each inventory has resource IDs, facts, region scope, coverage and a content hash. The lab uses fixed identities and seeded settings.
2. A registry pairs thirty metadata files with Python functions. Those functions return Finding objects. Reports separately calculate visible findings and compliance evidence. A missing fact yields MANUAL.
3. Five YAML definitions name predicates, relationship effects, proof operations and repair fields. The analyzer evaluates predicates against the inventory. It builds a NetworkX directed graph and searches bounded simple paths (six hops, up to 100 routes per pair). A self-management edge remains local to the principal. No hidden transitive permission is inferred.
4. Replay saves the actor, target and operation for each step and hashes that plan. A local sandbox holds the registered file behind a policy gate. Business assertions run before and after. Logged evidence uses allowlisted fields and the observed digest.
5. The lab fixer applies one patch to a copy, measures the same plan, retains both graphs and commits the changed lab state only when its stated success condition and business assertions hold. A modeled precondition can disappear without a network denial.
6. The report joins findings, graph relationships, before/after results and the exact patch. Startup time, OS-assigned ports and short-lived tokens never determine a verdict.

## Provider extension

Implement the Provider.collect(regions) interface, normalize your resources into a versioned inventory and add a provider-specific schema validator. Register the provider in the CLI, add check metadata/functions and golden good/bad/unknown resources. Azure role assignments and GCP IAM bindings require their own authorization semantics. Reporting, metrics and view filtering can be reused.

## Suggested time budget

At 30 hours each week: week 1 packaging/canary, week 2 six collectors, week 3 working scanner and reports, week 4 check catalogue and accuracy, week 5 policy reasoning and graph, week 6 saved-plan replay and patches, week 7 timed offline demo, week 8 verification and oral defence. The proposed fallback floor is 20 tested checks across all six services with the complete T1 loop, T2/T3 decisions, modeled T4, T5 multiplier, preservation of intended access and an offline report. This package contains all 30 checks.
