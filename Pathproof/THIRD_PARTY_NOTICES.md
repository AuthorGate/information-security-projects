# Third-party components

The project depends on PyYAML, NetworkX, Jinja2, boto3/botocore, Moto, pyvis and pytest. Each distribution carries its own license. Source installation obtains the dependencies listed in pyproject.toml. When an installed pyvis distribution includes vis-network, the renderer embeds its JavaScript bundle in the emitted HTML, preserving its bundled license/header text. The supplied fallback report uses PathProof's static SVG renderer.

Product names and benchmark references identify the technologies under discussion. PathProof is an independent classroom project. The metadata contains original short check descriptions with links to the relevant public crosswalk and technique catalogue.
