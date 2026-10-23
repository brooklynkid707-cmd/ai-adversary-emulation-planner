.PHONY: all kb validate plan coverage roe brief test clean

all: kb validate plan coverage roe brief test

kb:
	python scripts/build_kb.py

validate:
	python -m aep validate-kb

plan:
	python -m aep plan --profile ransomware-affiliate --env env/hospital.yaml --out plans/

coverage: plan
	python -m aep coverage --plan plans/ransomware-affiliate-plan.json --rules env/deployed_rules.csv --out plans/

roe: plan
	python -m aep roe --plan plans/ransomware-affiliate-plan.json --out plans/

brief: plan
	python -m aep brief --plan plans/ransomware-affiliate-plan.json --backend template --out plans/

test:
	python -m pytest -q

clean:
	rm -rf plans/*.json plans/*.md .pytest_cache **/__pycache__
