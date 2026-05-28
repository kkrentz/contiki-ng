#!/bin/bash

set -e

echo "t;name;event;counter;address" > statistics/$3/$2.csv

iotlab-experiment submit ${reservation_opt} -n $2 -d $1 -l strasbourg,openmoteb,1+3-6+9-12+14-17+19+21-37 > submit.json
experiment_id=$(jq '.id' submit.json)
rm submit.json
iotlab-experiment wait -i ${experiment_id}
iotlab-node -i ${experiment_id} --flash build/openmote/openmote-b/sink.openmote -l strasbourg,openmoteb,37
iotlab-node -i ${experiment_id} --flash build/openmote/openmote-b/source.openmote -l strasbourg,openmoteb,1+3-6+9-12+14-17+19+21-36
ssh kkrentz@strasbourg.iot-lab.info "serial_aggregator -i ${experiment_id}" >> statistics/$3/$2.csv

echo "t;name;type;address;rx;tx;total" > statistics/$3/$2-energy.csv
sed '/energy/!d' statistics/$3/$2.csv >> statistics/$3/$2-energy.csv
sed -i '/energy/d' statistics/$3/$2.csv
