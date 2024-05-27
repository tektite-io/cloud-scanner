PWD=$(shell pwd)
IMAGE_REPOSITORY?=quay.io/deepfenceio
TEKTITE_IMAGE_REPOSITORY?=tektite
DF_IMG_TAG?=latest
TEKTITE_OZONE_IMG_TAG?=2.2.0-ozone

.PHONY: bootstrap docker push steampipe-docker steampipe-docker-push

bootstrap:
	git submodule update --init --recursive --remote

steampipe-docker:
	docker build -t $(IMAGE_REPOSITORY)/steampipe:$(DF_IMG_TAG) -f Dockerfile.steampipe $(PWD)

steampipe-docker-push:
	docker tag $(IMAGE_REPOSITORY)/steampipe:$(DF_IMG_TAG) $(IMAGE_REPOSITORY)/steampipe:0.20.x
	docker push $(IMAGE_REPOSITORY)/steampipe:0.20.x

docker:
	docker pull $(IMAGE_REPOSITORY)/steampipe:0.20.x
	docker tag $(IMAGE_REPOSITORY)/steampipe:0.20.x $(IMAGE_REPOSITORY)/steampipe:$(DF_IMG_TAG)
	docker build --no-cache --build-arg IMAGE_REPOSITORY=$(IMAGE_REPOSITORY) --build-arg DF_IMG_TAG=$(DF_IMG_TAG) -t $(TEKTITE_IMAGE_REPOSITORY)/cloud-scanner:$(TEKTITE_OZONE_IMG_TAG) -f Dockerfile .

push: docker
	docker push $(TEKTITE_IMAGE_REPOSITORY)/cloud-scanner:$(TEKTITE_OZONE_IMG_TAG)
