#!/bin/bash

if [ -z ${VERSION} ]; then
    echo "no version environment variable 'VERSION' set"
    exit 0
fi

if [ -z ${REPOSITORY} ]; then
    echo "no repository variable 'REPOSITORY' set"
    exit 0
fi

#build for linux/amd64
env GOOS=linux GOARCH=amd64 go build -o build/go-tiny-mfa-amd64
#build for linux/arm64
env GOOS=linux GOARCH=arm64 GOARM=7 go build -o build/go-tiny-mfa-arm64
#build for linux/arm
env GOOS=linux GOARCH=arm GOARM=6 go build -o build/go-tiny-mfa-arm

#purge old manifest
docker manifest push --purge ${REPOSITORY}/go-tiny-mfa
docker manifest push --purge ${REPOSITORY}/go-tiny-mfa:${VERSION}
#remove all containers
docker system prune --volumes --all -f

#create docker image for linux/amd64
docker buildx build --load -t ${REPOSITORY}/go-tiny-mfa:amd64 --platform=linux/amd64 -f Dockerfile_amd64 .
#create docker image for linux/arm64
docker buildx build --load -t ${REPOSITORY}/go-tiny-mfa:arm64 --platform=linux/arm64 -f Dockerfile_arm64 .
#create docker image for linux/arm
docker buildx build --load -t ${REPOSITORY}/go-tiny-mfa:arm --platform=linux/arm/v7 -f Dockerfile_arm .

#push images to registry
docker push ${REPOSITORY}/go-tiny-mfa:arm
docker push ${REPOSITORY}/go-tiny-mfa:arm64
docker push ${REPOSITORY}/go-tiny-mfa:amd64

#create new :latest manifest 
docker manifest create \
            ${REPOSITORY}/go-tiny-mfa \
            ${REPOSITORY}/go-tiny-mfa:amd64 \
            ${REPOSITORY}/go-tiny-mfa:arm64 \
            ${REPOSITORY}/go-tiny-mfa:arm

#create new :VERSION manifest 
docker manifest create \
            ${REPOSITORY}/go-tiny-mfa:${VERSION} \
            ${REPOSITORY}/go-tiny-mfa:amd64 \
            ${REPOSITORY}/go-tiny-mfa:arm64 \
            ${REPOSITORY}/go-tiny-mfa:arm

#push manifest to registry
docker manifest push ${REPOSITORY}/go-tiny-mfa
docker manifest push ${REPOSITORY}/go-tiny-mfa:${VERSION}