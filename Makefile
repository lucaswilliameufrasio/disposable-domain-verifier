.PHONY: deploy

## Build and deploy the API to an interactively selected SSH host.
deploy:
	cargo run --bin deploy
