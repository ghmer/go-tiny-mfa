pipeline {
    agent any
    parameters {
        string(name: 'REPOSITORY', defaultValue: params.REPOSITORY ?:'', description: '')
        string(name: 'VERSION', defaultValue: params.VERSION ?:'', description: '')
        string(name: 'LDFLAGS', defaultValue: params.LDFLAGS ?:'-s -w', description: '')
        string(name: 'AMD64TAG', defaultValue: params.AMD64TAG ?:'amd64', description: '')
        string(name: 'ARM64TAG', defaultValue: params.ARM64TAG ?:'arm64', description: '')
        string(name: 'ARMTAG', defaultValue: params.ARMTAG ?:'arm', description: '')
        booleanParam(name: 'PRODUCTION', defaultValue: params.PRODUCTION ?:false, description: '')
    }

    tools {
        go "Golang"
    }

    stages {
        stage('Build') {
            steps {
                sh "env GOOS=linux GOARCH=amd64 go build -ldflags '${params.LDFLAGS}' -o build/go-tiny-mfa-amd64"                
                sh "env GOOS=linux GOARCH=arm64 GOARM=7 go build -ldflags '${params.LDFLAGS}' -o build/go-tiny-mfa-arm64"
                sh "env GOOS=linux GOARCH=arm GOARM=6 go build -ldflags '${params.LDFLAGS}' -o build/go-tiny-mfa-arm"
                
                sh """
                    docker buildx build --load --tag ${params.REPOSITORY}/go-tiny-mfa:${params.AMD64TAG} \
                        --platform=linux/amd64  --build-arg ARCH=amd64  --label version=${params.VERSION} \
                        --file Dockerfile .
                """   
               
                sh """
                    docker buildx build --load --tag ${params.REPOSITORY}/go-tiny-mfa:${params.ARM64TAG} \
                        --platform=linux/amd64  --build-arg ARCH=arm64 --label version=${params.VERSION} \
                        --file Dockerfile .
                """
                
                sh """
                    docker buildx build --load --tag ${params.REPOSITORY}/go-tiny-mfa:${params.ARMTAG} \
                        --platform=linux/amd64  --build-arg ARCH=arm --label version=${params.VERSION} \
                        --file Dockerfile .
                """
            }
        }
        stage('Push to registry') {
            steps {
                sh "docker push ${params.REPOSITORY}/go-tiny-mfa:${params.ARMTAG}"
                sh "docker push ${params.REPOSITORY}/go-tiny-mfa:${params.ARM64TAG}"
                sh "docker push ${params.REPOSITORY}/go-tiny-mfa:${params.AMD64TAG}"
            }
        }
        stage('Create manifests') {
            steps {
                script {
                    if(params.PRODUCTION) {
                        stage('Production') {
                            sh """
                                docker manifest create --amend \
                                    ${params.REPOSITORY}/go-tiny-mfa \
                                    ${params.REPOSITORY}/go-tiny-mfa:${params.AMD64TAG} \
                                    ${params.REPOSITORY}/go-tiny-mfa:${params.ARM64TAG} \
                                    ${params.REPOSITORY}/go-tiny-mfa:${params.ARMTAG}
                            """
                            
                            sh """
                                docker manifest create --amend \
                                    ${params.REPOSITORY}/go-tiny-mfa:${VERSION} \
                                    ${params.REPOSITORY}/go-tiny-mfa:${params.AMD64TAG} \
                                    ${params.REPOSITORY}/go-tiny-mfa:${params.ARM64TAG} \
                                    ${params.REPOSITORY}/go-tiny-mfa:${params.ARMTAG}
                            """

                            sh "docker manifest push ${params.REPOSITORY}/go-tiny-mfa"
                            sh "docker manifest push ${params.REPOSITORY}/go-tiny-mfa:${VERSION}"
                        }
                    } else {
                        stage('Development') {
                            sh "docker push ${params.REPOSITORY}/go-tiny-mfa:${params.AMD64TAG}"
                            sh "docker push ${params.REPOSITORY}/go-tiny-mfa:${params.ARM64TAG}"
                            sh "docker push ${params.REPOSITORY}/go-tiny-mfa:${params.ARMTAG}"

                            sh """
                            docker manifest create --amend \
                                        ${params.REPOSITORY}/go-tiny-mfa:development \
                                        ${params.REPOSITORY}/go-tiny-mfa:${params.AMD64TAG} \
                                        ${params.REPOSITORY}/go-tiny-mfa:${params.ARM64TAG} \
                                        ${params.REPOSITORY}/go-tiny-mfa:${params.ARMTAG}
                            """
                            sh "docker manifest push ${params.REPOSITORY}/go-tiny-mfa:development"
                        }
                    }
                }
            }
        }
    }
}
