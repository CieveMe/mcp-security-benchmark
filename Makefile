# MCP security benchmark - convenience entry points.
.PHONY: help list run summary test clean

PYTHON ?= python3

help:
	@echo "make list     - list targets and probe cases"
	@echo "make run      - run every target and write results/"
	@echo "make summary  - rebuild results/SUMMARY.md from existing scorecards"
	@echo "make test     - classifier unit tests"

list:
	$(PYTHON) -m bench list

run:
	$(PYTHON) -m bench run

summary:
	$(PYTHON) -m bench summary

test:
	$(PYTHON) -m unittest discover -s tests -v

clean:
	$(PYTHON) -c "import shutil,pathlib;[shutil.rmtree(p, ignore_errors=True) for p in [pathlib.Path('bench/__pycache__'), pathlib.Path('tests/__pycache__')]]"
