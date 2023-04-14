TIMEOUT(7200000); /* 2h */

while (true) {
  if (msg.contains('done')) {
    break;
  }
  if (msg.contains('1 third')) {
    mote.getSimulation().getRadioMedium().deteriorateLink(mote1.getInterfaces().getRadio(), mote3.getInterfaces().getRadio());
  } else if (msg.contains('2 thirds')) {
    mote.getSimulation().getRadioMedium().improveLink(mote1.getInterfaces().getRadio(), mote3.getInterfaces().getRadio());
  } else if (msg.contains('started')) {
    if (msg.contains('1 started')) {
      mote1 = mote;
    } else if (msg.contains('3 started')) {
      mote3 = mote;
    }
  } else {
    log.log(msg + "\n");
  }
  YIELD();
}
log.testOK();
