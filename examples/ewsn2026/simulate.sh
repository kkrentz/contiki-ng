#!/bin/bash

set -e

experiments=( orchestra csl-classic-blind csl-classic-ml csl-classic-ml-sleepless )
rates=( 25 50 100 200 400 )

gradle -p ../../tools/cooja jar

for experiment in "${experiments[@]}"
do
  for rate in "${rates[@]}"
  do
    name=$experiment-$rate
    mkdir -p temp/$name
    pushd temp/$name
    cp ../../simulation.csc .
    ln -sf ../../script.js script.js
    ln -sf ../../project-conf-csl.h project-conf-csl.h
    ln -sf ../../project-conf-tsch.h project-conf-tsch.h
    ln -sf ../../sink.c sink.c
    ln -sf ../../sink-source.h sink-source.h
    ln -sf ../../source.c source.c
    cp ../../configs/${experiment}.mk Makefile
    echo "MAKE_WITH_RATE=${rate}" >> Makefile
    echo "CONTIKI=../../../.." >> Makefile
    cat ../../Makefile >> Makefile

    java -jar ../../../../tools/cooja/build/libs/cooja.jar \
         simulation.csc --no-gui --random-seed=${rate} \
         && tail -n +2 COOJA.testlog | head -n -2 > ../../statistics/$name.csv \
         && echo "t;name;type;address;rx;tx;total" > ../../statistics/$name-energy.csv \
         && sed '/energy/!d' ../../statistics/$name.csv >> ../../statistics/$name-energy.csv \
         && sed -i '/energy/d' ../../statistics/$name.csv &
    sleep 1
    popd
  done
  wait
done

rm -rf temp
