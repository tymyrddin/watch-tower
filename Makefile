.PHONY: start init stop clean import triage

start:
	docker compose up -d

init:
	bash scripts/init-lab.sh

stop:
	docker compose stop

clean:
	docker compose down -v

import:
	bash scripts/import.sh --example

triage:
	bash scripts/triage.sh
