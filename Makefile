.PHONY: bench test install

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

bench:
	python benchmark/run_bench.py
