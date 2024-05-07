TIMEOUT(1000000, if(lastCounter != 0 && lostCounters == 0) { log.testOK(); } );

lastCounter = 0;
lostCounters = 0;

while(true) {
    YIELD();
    if(msg.startsWith("received")) {
        data = msg.split(" ");
        counter = parseInt(data[1]);
        if(counter != lastCounter + 1) {
          lostCounters += counter - lastCounter - 1;
        }
        log.log("" + counter + " " + lostCounters + " " + lastCounter + "\n");
        lastCounter = counter;
    }
}
