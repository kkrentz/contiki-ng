TIMEOUT(1980000, log.testOK())

while (true) {
  log.log(msg + "\n");
  YIELD();
}
