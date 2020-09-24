version=$1

echo "=======oauth2======="

mvn clean install -Dmaven.test.skip=true

docker build -f docker/dev.Dockerfile -t 192.168.10.124:8889/public/oauth2:"${version}" .
docker push 192.168.10.124:8889/public/oauth2:"${version}"
docker rmi -f 192.168.10.124:8889/public/oauth2:"${version}"

#docker run -d -p 9661:8080 --name oauth2-server --hostname oauth2-server --network cloud-demo 192.168.10.124:8889/public/oauth2:latest