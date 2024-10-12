pipeline {
    agent none
    environment {
        DOCKERHUB_CREDENTIALS = credentials('DockerLogin')
        SNYK_CREDENTIALS = credentials('SnykToken')
        SONARQUBE_CREDENTIALS = credentials('SonarToken')
        DEPLOY_USERNAME = 'jtf01645' // Deployment username variable
        TARGET_IP = '192.168.1.19' // Target IP for deployment variable
        SONARQUBE_IP = '192.168.1.19' // SonarQube IP variable
    }
    options {
        skipStagesAfterUnstable()
    }
    stages {
        /*
        stage('Secret Scanning Using Trufflehog') {
            agent {
                docker {
                    image 'trufflesecurity/trufflehog:latest'
                    args '-u root --entrypoint='
                }
            }
            steps {
                sh 'trufflehog filesystem . --exclude-paths trufflehog-excluded-paths.txt --json > trufflehog-scan-result.json'
                sh 'cat trufflehog-scan-result.json'
                archiveArtifacts artifacts: 'trufflehog-scan-result.json'
            }
        }
        stage('Build') {
            agent {
                docker {
                    image 'maven:3.9.9-eclipse-temurin-21-alpine'
                    args '-u root'
                }
            }
            steps {
                sh 'mvn -B -DskipTests clean package'
            }
        }
        stage('Test') {
            agent {
                docker {
                    image 'maven:3.9.9-eclipse-temurin-21-alpine'
                    args '-u root'
                }
            }
            steps {
                sh 'mvn test -Pcoverage'
            }
            post {
                always {
                    junit 'target/surefire-reports/*.xml'
                }
            }
        }
        stage('SCA Snyk Test') {
            agent {
                docker {
                    image 'snyk/snyk:node'
                    args '-u root --network host --env SNYK_TOKEN=$SNYK_CREDENTIALS_PSW --entrypoint='
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh 'snyk test --json > snyk-scan-report.json'
                }
                sh 'cat snyk-scan-report.json'
                archiveArtifacts artifacts: 'snyk-scan-report.json'
            }
        }
        stage('SCA Trivy Scan Dockerfile Misconfiguration') {
            agent {
                docker {
                    image 'aquasec/trivy:latest'
                    args '-u root --network host --entrypoint='
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh 'trivy config Dockerfile --exit-code=1 --format json > trivy-scan-dockerfile-report.json'
                }
                sh 'cat trivy-scan-dockerfile-report.json'
                archiveArtifacts artifacts: 'trivy-scan-dockerfile-report.json'
            }
        }
        stage('SAST Snyk') {
            agent {
                docker {
                    image 'snyk/snyk:node'
                    args '-u root --network host --env SNYK_TOKEN=$SNYK_CREDENTIALS_PSW --entrypoint='
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh 'snyk code test --json > snyk-sast-report.json'
                }
                archiveArtifacts artifacts: 'snyk-sast-report.json'
            }
        }
        stage('SAST SonarQube') {
            agent {
                docker {
                    image 'maven:3.9.9-eclipse-temurin-21-alpine'
                    args '-u root --network host'
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                    mvn sonar:sonar \
                        -Dsonar.token=$SONARQUBE_CREDENTIALS_PSW \
                        -Dsonar.projectKey=WebGoat \
                        -Dsonar.qualitygate.wait=true \
                        -Dsonar.host.url=http://$SONARQUBE_IP:9000 \
                        -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco-unit-test-coverage-report/jacoco.xml
                    '''
                }
            }
        }
        stage('Build Docker Image and Push to Docker Registry') {
            agent {
                docker {
                    image 'docker:dind'
                    args '--user root --network host -v /var/run/docker.sock:/var/run/docker.sock'
                }
            }
            steps {
                sh 'echo $DOCKERHUB_CREDENTIALS_PSW | docker login -u $DOCKERHUB_CREDENTIALS_USR --password-stdin'
                sh 'docker build -t xenjutsu/webgoat:0.1 .'
                sh 'docker push xenjutsu/webgoat:0.1'
            }
        }
        */
        stage('Deploy Docker Image') {
            agent {
                docker {
                    image 'kroniak/ssh-client'
                    args '--user root --network host'
                }
            }
            steps {
                withCredentials([sshUserPrivateKey(credentialsId: "DeploymentSSHKey", keyFileVariable: 'keyfile')]) {
                    sh '''
                    ssh -i ${keyfile} -o StrictHostKeyChecking=no $DEPLOY_USERNAME@$TARGET_IP "
                        echo $DOCKERHUB_CREDENTIALS_PSW | docker login -u $DOCKERHUB_CREDENTIALS_USR --password-stdin &&
                        docker pull xenjutsu/webgoat:0.1 &&
                        docker rm --force webgoat &&
                        docker run -it --detach --network host --name webgoat xenjutsu/webgoat:0.1
                    "
                    '''
                }
            }
        }
        stage('DAST Wapiti') {
            agent {
                docker {
                    image 'xenjutsu/wapiti:3.2.0'
                    args '--user root --network host --entrypoint='
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh 'wapiti -u http://$TARGET_IP:8080/WebGoat -f xml -o wapiti-report.xml'
                }
                archiveArtifacts artifacts: 'wapiti-report.xml'
            }
        }
        stage('DAST Nuclei') {
            agent {
                docker {
                    image 'projectdiscovery/nuclei'
                    args '--user root --network host --entrypoint='
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh 'nuclei -u http://$TARGET_IP:8080/WebGoat -nc -j > nuclei-report.json'
                    sh 'cat nuclei-report.json'
                }
                archiveArtifacts artifacts: 'nuclei-report.json'
            }
        }
        stage('DAST OWASP ZAP') {
            agent {
                docker {
                    image 'ghcr.io/zaproxy/zaproxy:weekly'
                    args '-u root --network host -v /var/run/docker.sock:/var/run/docker.sock --entrypoint= -v .:/zap/wrk/:rw'
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh 'zap-baseline.py -t http://$TARGET_IP:8080/WebGoat -r zapbaseline.html -x zapbaseline.xml'
                }
                sh 'cp /zap/wrk/zapbaseline.html ./zapbaseline.html'
                sh 'cp /zap/wrk/zapbaseline.xml ./zapbaseline.xml'
                archiveArtifacts artifacts: 'zapbaseline.html'
                archiveArtifacts artifacts: 'zapbaseline.xml'
            }
        }
    }
}
