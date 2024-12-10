login-github-registry:
	echo $(GITHUB_DOCKER_IMAGE_PUSH_TOKEN) | docker login ghcr.io -u $(GITHUB_USERNAME) --password-stdin

image:
	docker build -t zsoft/permission-gateway .

