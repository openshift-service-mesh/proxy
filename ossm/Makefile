.PHONY: ossm-update-envoy-sha ossm-update-deps ossm-update-everything

ossm-update-envoy-sha:
	@./scripts/update_envoy.sh

ossm-update-deps:
	@ossm/scripts/update-deps.sh

ossm-update-everything: ossm-update-envoy-sha ossm-update-deps
