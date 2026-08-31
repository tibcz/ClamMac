# ClamMac -- development and build tasks.
#
#   make venv     create .venv and install everything needed
#   make run      run from source
#   make test     run the test suite
#   make lint     run ruff
#   make check    lint + test
#   make icon     regenerate the application icon
#   make app      build ClamMac.app          (macOS only)
#   make dmg      build ClamMac.dmg          (macOS only)
#   make clean    remove build output

PYTHON      ?= python3
VENV        := .venv
VENV_PYTHON := $(VENV)/bin/python
PIP         := $(VENV)/bin/pip

.DEFAULT_GOAL := help
.PHONY: help venv run test lint format check icon app dmg clean distclean

help:
	@grep -E '^#   make' Makefile | sed 's/^#   /  /'

$(VENV_PYTHON):
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip wheel
	$(PIP) install -r requirements-dev.txt

venv: $(VENV_PYTHON)
	@echo "Environment ready. Activate with: source $(VENV)/bin/activate"

run: venv
	$(VENV_PYTHON) -m clammac

test: venv
	$(VENV_PYTHON) -m pytest

lint: venv
	$(VENV_PYTHON) -m ruff check clammac tests packaging scripts

format: venv
	$(VENV_PYTHON) -m ruff check --fix clammac tests packaging scripts

check: lint test

icon: venv
	$(VENV_PYTHON) packaging/build_app.py --icon-only

app: venv
	$(VENV_PYTHON) packaging/build_app.py --app-only

dmg: venv
	$(VENV_PYTHON) packaging/build_app.py

clean:
	rm -rf build dist
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov

distclean: clean
	rm -rf $(VENV) *.egg-info
