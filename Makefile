PYTHON ?= python3
export PYTHONPATH := src
.PHONY: run test verify clean
run:
	$(PYTHON) -m soclab run --output artifacts
verify:
	$(PYTHON) -m soclab verify --events artifacts/events.jsonl --output artifacts/verified

test:
	$(PYTHON) -m unittest discover -s tests -v
clean:
	rm -rf artifacts
