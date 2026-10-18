# Contributing to SurfaceSentry

Thank you for your interest in improving SurfaceSentry!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/surfacesentry.git
   cd surfacesentry
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

4. Run the test suite:
   ```bash
   pytest -v
   ```

## Writing Custom Plugins

SurfaceSentry features a modular plugin architecture. To create a new check:

1. Create a Python file in `surfacesentry/plugins/` (e.g., `my_check.py`).
2. Subclass `BasePlugin`:
   ```python
   from surfacesentry.plugins.base import BasePlugin
   from surfacesentry.core.models import Asset, Finding

   class MyCustomPlugin(BasePlugin):
       name = "my_custom_check"
       description = "Detects specific misconfigurations"

       def run(self, asset: Asset) -> list[Finding]:
           findings = []
           # Inspection logic
           return findings
   ```
3. Register your plugin in `surfacesentry/plugins/manager.py`.

## Pull Request Guidelines

- Ensure all existing tests pass (`pytest`).
- Add unit tests for any new features or bug fixes.
- Maintain authorized testing principles: only passive or non-destructive checks are accepted in the core suite.
