pipeline {
    agent any
    parameters {
        string(name: 'REPOSITORY', defaultValue: params.REPOSITORY ?:'', description: '')
        string(name: 'VERSION', defaultValue: params.VERSION ?:'v0.2.8', description: '')
        string(name: 'AMD64TAG', defaultValue: params.AMD64TAG ?:'amd64', description: '')
        string(name: 'ARM64TAG', defaultValue: params.ARM64TAG ?:'arm64', description: '')
        string(name: 'ARMTAG', defaultValue: params.ARMTAG ?:'arm', description: '')
        booleanParam(name: 'PRODUCTION', defaultValue: params.PRODUCTION ?:false, description: '')
    }

    stages {
        stage('Build') {
            steps {
                sh """
                    docker buildx build --load --tag ${params.REPOSITORY}/go-tiny-mfa:${params.AMD64TAG} \
                        --platform=linux/amd64  --build-arg arch=amd64  --label version=${params.VERSION} \
                        --file Dockerfile .
                """   
               
                sh """
                    docker buildx build --load --tag ${params.REPOSITORY}/go-tiny-mfa:${params.ARM64TAG} \
                        --platform=linux/arm64/v8  --build-arg arch=arm64 --label version=${params.VERSION} \
                        --file Dockerfile .
                """
                
                sh """
                    docker buildx build --load --tag ${params.REPOSITORY}/go-tiny-mfa:${params.ARMTAG} \
                        --platform=linux/arm  --build-arg arch=arm --label version=${params.VERSION} \
                        --file Dockerfile .
                """
            }
        }
        stage('Push to registry') {
            steps {
                sh "docker push ${params.REPOSITORY}/go-tiny-mfa:${params.AMD64TAG}"
                sh "docker push ${params.REPOSITORY}/go-tiny-mfa:${params.ARM64TAG}"
                sh "docker push ${params.REPOSITORY}/go-tiny-mfa:${params.ARMTAG}"
            }
        }
        stage('Create manifests') {
            steps {
                script {
                    if(params.PRODUCTION) {
                        stage('Production') {
                            sh "docker manifest rm ${params.REPOSITORY}/go-tiny-mfa"
                            sh "docker manifest rm ${params.REPOSITORY}/go-tiny-mfa:${VERSION}"
                            
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
                            sh "docker manifest rm ${params.REPOSITORY}/go-tiny-mfa:development"

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
