#!/bin/bash

#build for linux/amd64
env GOOS=linux GOARCH=amd64 go build -o build/go-tiny-mfa-amd64
#build for linux/arm64
env GOOS=linux GOARCH=arm64 GOARM=7 go build -o build/go-tiny-mfa-arm64
#build for linux/arm
env GOOS=linux GOARCH=arm GOARM=6 go build -o build/go-tiny-mfa-arm

#purge old manifest
docker manifest push --purge registry.parzival.link/go-tiny-mfa
docker manifest push --purge registry.parzival.link/go-tiny-mfa:${VERSION}
#remove all containers
docker system prune --volumes --all -f

#create docker image for linux/amd64
docker buildx build --load -t registry.parzival.link/go-tiny-mfa:amd64 --platform=linux/amd64 -f Dockerfile_amd64 .
#create docker image for linux/arm64
docker buildx build --load -t registry.parzival.link/go-tiny-mfa:arm64 --platform=linux/arm64 -f Dockerfile_arm64 .
#create docker image for linux/arm
docker buildx build --load -t registry.parzival.link/go-tiny-mfa:arm --platform=linux/arm/v7 -f Dockerfile_arm .

#push images to registry
docker push registry.parzival.link/go-tiny-mfa:arm
docker push registry.parzival.link/go-tiny-mfa:arm64
docker push registry.parzival.link/go-tiny-mfa:amd64

#create new :latest manifest 
docker manifest create \
            registry.parzival.link/go-tiny-mfa \
            registry.parzival.link/go-tiny-mfa:amd64 \
            registry.parzival.link/go-tiny-mfa:arm64 \
            registry.parzival.link/go-tiny-mfa:arm

#create new :VERSION manifest 
docker manifest create \
            registry.parzival.link/go-tiny-mfa:${VERSION} \
            registry.parzival.link/go-tiny-mfa:amd64 \
            registry.parzival.link/go-tiny-mfa:arm64 \
            registry.parzival.link/go-tiny-mfa:arm

#push manifest to registry
docker manifest push registry.parzival.link/go-tiny-mfa
docker manifest push registry.parzival.link/go-tiny-mfa:${VERSION}