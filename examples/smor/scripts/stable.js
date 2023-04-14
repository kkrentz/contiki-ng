TIMEOUT(7200000); /* 2h */

while (true) {
  if (msg.contains('done')) {
    break;
  }
  if (!msg.contains('started') && !msg.contains('third')) {
    log.log(msg + "\n");
  }
  YIELD();
}
log.testOK();
