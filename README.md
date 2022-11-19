# samsungac
Old (port 2787) samsung air conditioner to MQTT bridge

# Installation and running
A docker file and a docker-compose file is provided to create a container.

```shell
docker-compose up -d --build
```
or, depending on docker version
```shell
docker compose up -d --build
```

Once started you need to scan for device and populate the config.json file. To do
so please use:

```shell
docker exec -ti <container_id> python3 main.py -i
```

and choose option d)

**NOTE: At the current stage the MQTT broker address is still hardcoded in the main.py 
file under the create_interface function. Before building the container please set 
this address to your local mqtt broker. This will be changed in next commits...
The one in the source code is not published and is a local broker.**


