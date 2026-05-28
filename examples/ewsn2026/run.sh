#!/bin/bash

set -e

duration=$(( 15 + 15 + 3))
rates=( 25 50 100 200 400 )

make TARGET=openmote BOARD=openmote-b savetarget

for rate in "${rates[@]}"
do
  # TSCH/Orchestra/ALICE
  make distclean
  make MAKE_WITH_ORCHESTRA=1 MAKE_WITH_RPL_STORING=1 MAKE_WITH_RATE=${rate} -j${nproc}
  ./fit.sh $duration orchestra-${rate}

  # CSL with RPL in storing mode and blind channel hopping
  make distclean
  make MAKE_WITH_RPL_STORING=1 MAKE_WITH_RATE=${rate} -j${nproc}
  ./fit.sh $duration csl-classic-blind-${rate}

  # CSL with RPL in storing mode and ML-based channel hopping
  make distclean
  make MAKE_WITH_RPL_STORING=1 MAKE_WITH_D_UCB=1 MAKE_WITH_RATE=${rate} -j${nproc}
  ./fit.sh $duration csl-classic-ml-${rate}

  # CSL with RPL in storing mode and ML-based channel hopping and increased wake-up rate
  make distclean
  make MAKE_WITH_RPL_STORING=1 MAKE_WITH_D_UCB=1 MAKE_WITH_RATE=${rate} MAKE_WITH_WAKE_UP_RATE=32 -j${nproc}
  ./fit.sh $duration csl-classic-ml-sleepless-${rate}
done
