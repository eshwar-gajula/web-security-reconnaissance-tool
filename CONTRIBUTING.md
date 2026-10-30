# Contributing

1. Use Python 3.11 or newer and install the development extra with `python -m pip install -e '.[dev]'`.
2. Keep the tool focused on bounded, authorized information collection.
3. Add tests using mocked DNS or a loopback-only HTTP server for behavior changes.
4. Run `python -m pytest` and `ruff check .` before opening a pull request.
5. Never commit real target inventories, reports, credentials, cookies, or authorization documents.

Changes that add credential testing, form submission, endpoint brute force, evasion, or exploit
behavior are outside the project's intended scope.
