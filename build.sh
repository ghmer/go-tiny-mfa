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

if [ -z ${REPOSITORY} ]; then
    echo "no repository variable 'REPOSITORY' set"
    exit 99
fi

LDFLAGS=""
ARMTAG="dev-arm"
ARM64TAG="dev-arm64"
AMD64TAG="dev-amd64"

if [[ ${PRODUCTION} == "true" ]]; then
    # production builds require version
    if [ -z ${VERSION} ]; then
        echo "no version environment variable 'VERSION' set"
        exit 99
    fi
    
    LDFLAGS="-s -w"
    ARMTAG="arm"
    ARM64TAG="arm64"
    AMD64TAG="amd64"
fi

#cleanup and prepare build directory
if [ -d ./build ]; then
    rm ./build/*
else 
    mkdir ./build
fi

clear
echo "building binaries"
#build for linux/amd64
env GOOS=linux GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o build/go-tiny-mfa-amd64
#build for linux/arm64
env GOOS=linux GOARCH=arm64 GOARM=7 go build -ldflags "${LDFLAGS}" -o build/go-tiny-mfa-arm64
#build for linux/arm
env GOOS=linux GOARCH=arm GOARM=6 go build -ldflags "${LDFLAGS}" -o build/go-tiny-mfa-arm

echo "remove existing containers"
#remove all containers
${DOCKER} system prune --volumes --all -f

echo "build new container"
#create docker image for linux/amd64
${DOCKER} buildx build --load --tag ${REPOSITORY}/go-tiny-mfa:${AMD64TAG} \
    --platform=linux/amd64  --build-arg ARCH=amd64 \
    --label version=${VERSION} --label commit=${COMMIT} \
    --label revision=${REVISION} --file Dockerfile .
#create docker image for linux/arm64
${DOCKER} buildx build --load --tag ${REPOSITORY}/go-tiny-mfa:${ARM64TAG} \
    --platform=linux/arm64  --build-arg ARCH=arm64 \
    --label version=${VERSION} --label commit=${COMMIT} \
    --label revision=${REVISION} --file Dockerfile .
#create docker image for linux/arm
${DOCKER} buildx build --load --tag ${REPOSITORY}/go-tiny-mfa:${ARMTAG}   \
    --platform=linux/arm/v6 --build-arg ARCH=arm   \
    --label version=${VERSION} --label commit=${COMMIT} \
    --label revision=${REVISION} --file Dockerfile .

echo "push containers to registry"
#push images to registry
${DOCKER} push ${REPOSITORY}/go-tiny-mfa:${ARMTAG}
${DOCKER} push ${REPOSITORY}/go-tiny-mfa:${ARM64TAG}
${DOCKER} push ${REPOSITORY}/go-tiny-mfa:${AMD64TAG}

#build for production?
if [[ ${PRODUCTION} == "true" ]]; then 
    echo "create production manifests";
    #purge old manifest
    ${DOCKER} manifest push --purge ${REPOSITORY}/go-tiny-mfa
    ${DOCKER} manifest push --purge ${REPOSITORY}/go-tiny-mfa:${VERSION}

    #create new :latest manifest 
    ${DOCKER} manifest create \
            ${REPOSITORY}/go-tiny-mfa \
            ${REPOSITORY}/go-tiny-mfa:${AMD64TAG} \
            ${REPOSITORY}/go-tiny-mfa:${ARM64TAG} \
            ${REPOSITORY}/go-tiny-mfa:${ARMTAG}

    #create new :VERSION manifest 
    ${DOCKER} manifest create \
            ${REPOSITORY}/go-tiny-mfa:${VERSION} \
            ${REPOSITORY}/go-tiny-mfa:${AMD64TAG} \
            ${REPOSITORY}/go-tiny-mfa:${ARM64TAG} \
            ${REPOSITORY}/go-tiny-mfa:${ARMTAG}

    echo "push manifests to registry";
    #push manifest to registry
    ${DOCKER} manifest push ${REPOSITORY}/go-tiny-mfa
    ${DOCKER} manifest push ${REPOSITORY}/go-tiny-mfa:${VERSION}
else 
    echo "create development manifests";
    #purge old manifest
    ${DOCKER} manifest push --purge ${REPOSITORY}/go-tiny-mfa:development

    #create new :latest manifest 
    ${DOCKER} manifest create \
                ${REPOSITORY}/go-tiny-mfa:development \
                ${REPOSITORY}/go-tiny-mfa:${AMD64TAG} \
                ${REPOSITORY}/go-tiny-mfa:${ARM64TAG} \
                ${REPOSITORY}/go-tiny-mfa:${ARMTAG} 

    echo "push manifests to registry";
    #push manifest to registry
    ${DOCKER} manifest push ${REPOSITORY}/go-tiny-mfa:development
fi

echo "done"
exit 0