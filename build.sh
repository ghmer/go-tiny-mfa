#!/bin/bash

DOCKER=$(which docker)
COMMIT=$(git rev-parse --short master)
REVISION=$(git rev-list --all --count)

#sanity checks
if [ -z ${DOCKER} ]; then
    echo "docker not found!"
    exit 99
fi

if [ -z ${REVISION} ]; then
    echo "no revision environment variable 'REVISION' set"
    exit 99
fi

if [ -z ${VERSION} ]; then
    echo "no version environment variable 'VERSION' set"
    exit 99
fi

if [ -z ${REPOSITORY} ]; then
    echo "no repository variable 'REPOSITORY' set"
    exit 99
fi

#cleanup and prepare build directory
if [ -d ./build ]; then
    rm ./build/*
else 
    mkdir ./build
fi

#build for linux/amd64
env GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o build/go-tiny-mfa-amd64
#build for linux/arm64
env GOOS=linux GOARCH=arm64 GOARM=7 go build -ldflags "-s -w" -o build/go-tiny-mfa-arm64
#build for linux/arm
env GOOS=linux GOARCH=arm GOARM=6 go build -ldflags "-s -w" -o build/go-tiny-mfa-arm

#purge old manifest
${DOCKER} manifest push --purge ${REPOSITORY}/go-tiny-mfa
${DOCKER} manifest push --purge ${REPOSITORY}/go-tiny-mfa:${VERSION}
#remove all containers
${DOCKER} system prune --volumes --all -f

#create docker image for linux/amd64
${DOCKER} buildx build --load --tag ${REPOSITORY}/go-tiny-mfa:amd64 \
    --platform=linux/amd64  --build-arg ARCH=amd64 \
    --label version=${VERSION} --label commit=${COMMIT} \
    --label revision=${REVISION} --file Dockerfile .
#create docker image for linux/arm64
${DOCKER} buildx build --load --tag ${REPOSITORY}/go-tiny-mfa:arm64 \
    --platform=linux/arm64  --build-arg ARCH=arm64 \
    --label version=${VERSION} --label commit=${COMMIT} \
    --label revision=${REVISION} --file Dockerfile .
#create docker image for linux/arm
${DOCKER} buildx build --load --tag ${REPOSITORY}/go-tiny-mfa:arm   \
    --platform=linux/arm/v6 --build-arg ARCH=arm   \
    --label version=${VERSION} --label commit=${COMMIT} \
    --label revision=${REVISION} --file Dockerfile .

#push images to registry
${DOCKER} push ${REPOSITORY}/go-tiny-mfa:arm
${DOCKER} push ${REPOSITORY}/go-tiny-mfa:arm64
${DOCKER} push ${REPOSITORY}/go-tiny-mfa:amd64

#create new :latest manifest 
${DOCKER} manifest create \
            ${REPOSITORY}/go-tiny-mfa \
            ${REPOSITORY}/go-tiny-mfa:amd64 \
            ${REPOSITORY}/go-tiny-mfa:arm64 \
            ${REPOSITORY}/go-tiny-mfa:arm

#create new :VERSION manifest 
${DOCKER} manifest create \
            ${REPOSITORY}/go-tiny-mfa:${VERSION} \
            ${REPOSITORY}/go-tiny-mfa:amd64 \
            ${REPOSITORY}/go-tiny-mfa:arm64 \
            ${REPOSITORY}/go-tiny-mfa:arm

#push manifest to registry
${DOCKER} manifest push ${REPOSITORY}/go-tiny-mfa
${DOCKER} manifest push ${REPOSITORY}/go-tiny-mfa:${VERSION}