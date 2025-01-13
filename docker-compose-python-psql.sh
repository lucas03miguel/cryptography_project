#
# ATTENTION: This will stop and delete all the running containers
# Comment out if you are using docker for other ativities
#
docker rm $(docker stop $(docker ps -a -q)) 


# # # Please comment back this command after your python setup works.
# This command should be uncommented only when you changed any of the Dockerfiles. In alternative, use it directly in the console.
docker-compose  -f docker-compose-python-psql.yml   build  --no-cache 


mkdir -p website/logs

# add  -d  to the command below if you want the containers running in background without logs
docker-compose -f docker-compose-python-psql.yml up --build