# samsungac
Old (port 2787) samsung air conditioner to MQTT bridge

# Installation
A docker file and a docker-compose file is provided to create a container.

**NOTE: At the current stage the MQTT broker address is still hardcoded in the main.py 
file under the create_interface function. Before building the container please set 
this address to your local mqtt broker. This will be changed in next commits...
The one in the source code is not published and is a local broker.**

To run the container execute from a shell after editing the main.py file:
```shell
docker-compose up --build -d
```



