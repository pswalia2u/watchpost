.PHONY: health shipments secrets

API ?= http://18.171.222.41

health:
	curl -sS $(API)/health | python3 -m json.tool

shipments:
	curl -sS $(API)/v1/shipments | python3 -m json.tool

secrets:
	curl -sS $(API)/v1/ci/secrets | python3 -m json.tool
