#!/bin/bash

env GOOS=linux GOARCH=amd64 go build -o build/go-tiny-mfa-amd64
env GOOS=linux GOARCH=arm64 GOARM=7 go build -o build/go-tiny-mfa-arm64
env GOOS=linux GOARCH=arm GOARM=6 go build -o build/go-tiny-mfa-arm

docker manifest push --purge registry.parzival.link/go-tiny-mfa
docker system prune --volumes --all

docker build -t registry.parzival.link/go-tiny-mfa:amd64 -f Dockerfile_amd64 .
docker build -t registry.parzival.link/go-tiny-mfa:arm64 -f Dockerfile_arm64 .
docker build -t registry.parzival.link/go-tiny-mfa:arm -f Dockerfile_arm .

docker buildx build -t registry.parzival.link/go-tiny-mfa:amd64 --platform=linux/amd64 -f Dockerfile_amd64 .
docker buildx build -t registry.parzival.link/go-tiny-mfa:arm64 --platform=linux/arm64 -f Dockerfile_arm64 .
docker buildx build -t registry.parzival.link/go-tiny-mfa:arm --platform=linux/arm/v7 -f Dockerfile_arm .

docker push registry.parzival.link/go-tiny-mfa:arm
docker push registry.parzival.link/go-tiny-mfa:arm64
docker push registry.parzival.link/go-tiny-mfa:amd64

docker manifest create \
            registry.parzival.link/go-tiny-mfa \
            registry.parzival.link/go-tiny-mfa:amd64 \
            registry.parzival.link/go-tiny-mfa:arm64 \
            registry.parzival.link/go-tiny-mfa:arm

docker manifest push registry.parzival.link/go-tiny-mfa