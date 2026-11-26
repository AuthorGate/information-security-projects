# PathProof

PathProof scans AWS configurations and saves the results as JSON, CSV, and HTML. Its offline demo tests whether removing one policy statement blocks an anonymous file read while preserving access for the authorized reader.

## Run the demo on Windows

Open PowerShell in the `Pathproof` folder. Use Python 3.11 or newer. The setup command downloads dependencies, so run it while online.

```powershell
python --version
python bootstrap.py
.\.venv\Scripts\pathproof.exe demo --narrate --out first-demo
Start-Process .\first-demo\report.html
```

Use a new output folder name each time. The demo runs locally and requires no AWS account. In the T1 scenario, the anonymous request changes from HTTP 200 to HTTP 403 after the fix. The authorized reader receives HTTP 200 both times.
## Run the demo on Kali Linux

Open a terminal in the `Pathproof` folder that contains `bootstrap.py`. Run setup while online. PathProof requires Python 3.11 or newer.

```bash
sudo apt update
sudo apt install python3 python3-venv
python3 --version
python3 bootstrap.py
.venv/bin/pathproof demo --narrate --out kali-demo
xdg-open kali-demo/report.html
```

`bootstrap.py` installs the project dependencies inside `.venv`. After setup, the demo can run offline. Use a new output folder name each time. On a headless system, copy `kali-demo/report.html` to a computer with a browser and open it there.

To run the tests:

```bash
.venv/bin/python -m pytest -q -rs
``` 
## Evidence and tests

- `demo-fallback/report.html` contains the saved demo results. Download it and open it in a browser.
- `demo-fallback/proofs.json` contains the before-and-after evidence.
- Run the test suite with `.\.venv\Scripts\python.exe -m pytest -q -rs`.

The local demo verifies behavior in the PathProof lab. Live AWS behavior was outside the verified scope.
