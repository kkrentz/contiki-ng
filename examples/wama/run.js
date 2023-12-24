TIMEOUT(7200000); /* 2h */

while (true) {
  if (msg.contains('done')) {
    break;
  }
  log.log(msg + "\n");
  YIELD();
}
log.testOK();
