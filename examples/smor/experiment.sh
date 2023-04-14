#!/bin/bash

set -e

experiments=( stable weak )
protocols=( null rpl rpl-p2p rpl-classic rpl-classic-p2p smor smor-more-agile smor-very-agile )
samples=2000
threads=4

gradle -p ../../tools/cooja jar

for experiment in "${experiments[@]}"
do
  mkdir -p R/$experiment/D
  mkdir -p R/$experiment/T
  mkdir -p R/$experiment/E

  for protocol in "${protocols[@]}"
  do
    pushd udp
    make distclean
    ln -sf Makefile.$protocol Makefile
    ln -sf project-conf.$protocol project-conf.h
    popd
    rm -rf temp
    mkdir temp

    for thread in `seq 1 $threads`
    do
      mkdir temp/$thread
      pushd temp/$thread/
      cp ../../udp.csc .
      ln -s ../../udp .
      ln -s ../../scripts/$experiment.js run.js
      popd
    done

    for seed in `seq 1 $samples`
    do
      pushd temp/$(($seed % $threads + 1))
      java -Xms400M \
          -Xmx2048M \
          --enable-preview \
          --enable-native-access ALL-UNNAMED \
          -jar ../../../../tools/cooja/build/libs/cooja.jar \
          udp.csc --no-gui --random-seed=$seed \
          && tail -n +2 COOJA.testlog | head -n -2 > temp.txt \
          && grep -E '^(D|Assertion)' temp.txt | cut -c 3- > ../../R/$experiment/D/$protocol-$seed.csv \
          && echo "time,node,type,kind,length" > ../../R/$experiment/T/$protocol-$seed.csv \
          && grep -E '^T' temp.txt | cut -c 3- >> ../../R/$experiment/T/$protocol-$seed.csv \
          && grep -E '^E' temp.txt | cut -c 3- > ../../R/$experiment/E/$protocol-$seed.csv \
          && rm temp.txt &
      sleep 1
      popd

      if (( $seed % $threads == 0 ))
      then
        wait
      fi
    done

    wait
  done
done

make -C udp distclean
rm -rf temp
