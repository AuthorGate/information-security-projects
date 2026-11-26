# Build verification

The standard-library runner collected 35 tests. Thirty passed. Five optional integration tests were skipped on this Linux build machine. The same test classes are discoverable by pytest. The exercised paths include all 30 checks on good, bad and unknown inputs, a test that deliberately breaks the raw security-group interpretation and observes recall falling, parser and CLI behavior, the HTTP canary/legitimate reader loop, all five fixes, view filtering, semantic equality of repeated runs, and the six collector normalizers driven by recorded-shaped responses.

Three separate fresh-process Python 3.13.5 demo runs using memory storage, the standard-library practice graph and static SVG took 0.458, 0.473 and 0.487 seconds. Each included lab startup, measurement, graph construction and report export. The three report.json files were byte-identical. These timings describe the build machine. Time the installed configuration on your presentation laptop.

| Integration | Build-machine status |
|---|---|
| Python 3.12 and 3.13 Linux test runners | Exercised with the standard-library unittest runner. |
| Python 3.11 syntax | Parsed all authored Python files using the 3.11 grammar. |
| Python 3.11 runtime and Windows bootstrap | Unverified on this machine. |
| NetworkX path enumeration | Implementation and install dependency present. The NetworkX-specific test was skipped because the package was unavailable. The fallback enumerator was exercised. |
| Moto server storage | Implementation and installation dependency present. The Moto-specific test was skipped because Moto and boto3 were unavailable. |
| Botocore Stubber | Two SDK tests included for installed environments. Both skipped here because boto3 was unavailable. |
| Live AWS | No account used. The consent-based integration test was skipped. Simulator response handling was tested with synthetic inputs. |
| pytest and interactive vis-network rendering | Dependencies were unavailable here. The test cases ran under unittest. The standalone fallback HTML uses static SVG and evidence tables. |
| Accuracy | Each of 30 checks matched its known-positive, known-negative and unknown case. Local results were precision 1.0, recall 1.0 and decision coverage 1.0 on the two labeled cases per check. |
| Fallback recording | A captured CLI run, displayed at reading speed, encoded as H.264 MP4 at 1280 by 800. |

The package index was unavailable to this environment. On the prepared laptop run python -m pytest -q -rs in the project environment. With dependencies installed and no AWS opt-in, only the live-account test should skip. Reach for this table when a classmate asks which behaviors were independently executed.
