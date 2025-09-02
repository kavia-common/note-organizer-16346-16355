# Linting and Static Analysis

Commands (from this directory) in the project's virtualenv:

- flake8
- pylint src
- mypy

If mypy or pylint are missing, install with:
  pip install -r requirements.txt

Configs:
- .flake8 (already present)
- pyproject.toml (pylint settings)
- mypy.ini (type checking settings)
