get_traffic_per_node <- function(d, number_of_nodes = 9) {
  traffic_per_node <- vector(length = number_of_nodes)
  for(node_id in seq(number_of_nodes)) {
    subdata <- subset(d, d$node == node_id)
    traffic_per_node[node_id] <- sum(subdata$length)
  }
  return (traffic_per_node)
}

seeds <- seq(32)
max_datagram <- 100
max_source <- 9
for(experiment in c("flat")) {
  protocols <- c("exp2", "exp4", "exp6", "cncr")
  protocol_labels <- protocols

  # delivery ratios
  delivery_ratios <- matrix(nrow = length(seeds), ncol = length(protocols))
  for(protocol_index in seq(length(protocols))) {
    for(seed in seeds) {
      file <- paste(getwd(), "/", experiment, "/D/", protocols[protocol_index], "-", seed, ".csv", sep = "")
      data <- read.table(file, header = T, sep = ",")
      received_datagrams_count <- 0
      for(s in seq(2, max_source)) {
        d <- subset(data, (datagram <= max_datagram) & (source == s))
        received_datagrams <- 1:max_datagram %in% d$datagram
        received_datagrams_count <- received_datagrams_count + sum(received_datagrams == TRUE)
      }
      delivery_ratios[seed, protocol_index] <- received_datagrams_count * 100 / ((max_source - 1) * max_datagram)
    }
  }
  delivery_ratio_means <- c()
  for(protocol_index in seq(length(protocols))) {
    delivery_ratio_means <- c(delivery_ratio_means, mean(delivery_ratios[, protocol_index]))
  }

  cairo_pdf(file = paste("delivery-ratios-", experiment, ".pdf", sep = ""), width = 5, height = 2.8)
  par(cex = 1)
  par(las = 1)
  par(mar = c(4.1, 4.1 + 9.5, 0.2, 0.1))
  centers <- barplot(delivery_ratio_means,
                     horiz = TRUE,
                     xlab = "mean PDR (in %)",
                     xlim = c(0, 160),
                     names = protocol_labels,
                     xaxt = "n")
  axis(1, at = seq(0, 100, 25))
  for(i in seq(length(protocols))) {
    text(delivery_ratio_means[i] + 30, centers[i], format(round(delivery_ratio_means[i], 3), nsmall = 3))
  }
  dev.off()

  # delays
  delay_means <- c()
  for(protocol_index in seq(length(protocols))) {
    delays <- c()
    for(seed in seeds) {
      file <- paste(getwd(), "/", experiment, "/D/", protocols[protocol_index], "-", seed, ".csv", sep = "")
      data <- read.table(file, header = T, sep = ",")
      data <- subset(data, datagram <= max_datagram)
      datagrams <- data$datagram
      # remove any duplicates
      for(d in datagrams) {
        rows <- which(data$datagram == d)
        if(length(rows) > 1) {
          rows_to_delete <- tail(rows, n = (length(rows) - 1))
          data <- data[-rows_to_delete,]
        }
      }
      delays <- c(delays, data$delay / 1000)
    }
    delays <- delays / 1000
    switch (
      protocol_index,
      exp2_delays <- delays,
      exp4_delays <- delays,
      exp6_delays <- delays,
      cncr_delays <- delays,
    )
    delay_means <- c(delay_means, mean(delays))
  }
  
  png(file = paste("delays-", experiment, ".png", sep = ""), width = 12, height = 2.8, units="in",res=72)
  par(cex = 1)
  par(las = 1)
  par(mar = c(4.1, 4.1 + 9.5, 0.2, 0.1))
  boxplot(
    exp2_delays, exp4_delays, exp6_delays, cncr_delays,
    names = protocol_labels,
    ylim = c(0,14.2),
    xaxt = "n",
    xlab = "delay (in s)",
    horizontal = TRUE)
  axis(1, cex.axis = 1.2, at = seq(0.0,14.2,1))
  dev.off()

  # traffic
  akes_traffic <- matrix(nrow = length(seeds), ncol = length(protocols))
  non_akes_traffic <- matrix(nrow = length(seeds), ncol = length(protocols))
  icmpv6_traffic <- matrix(nrow = length(seeds), ncol = length(protocols))
  non_icmpv6_traffic <- matrix(nrow = length(seeds), ncol = length(protocols))
  for(protocol_index in seq(length(protocols))) {
    for(seed in seeds) {
      file <- paste(getwd(), "/", experiment, "/T/", protocols[protocol_index], "-", seed, ".csv", sep = "")
      data <- read.table(file, header = T, sep = ",")
      akes <- subset(data, (data$type == 3) & (data$kind != 15))
      akes_traffic[seed, protocol_index] <- mean(get_traffic_per_node(akes))
      non_akes <- subset(data, (data$type == 3) & (data$kind == 15))
      non_akes_traffic[seed, protocol_index] <- mean(get_traffic_per_node(non_akes))
      icmpv6 <- subset(data, (data$type == 1) & (data$kind == 58))
      icmpv6_traffic[seed, protocol_index] <- mean(get_traffic_per_node(icmpv6))
      non_icmpv6 <- subset(data, (data$type == 1) & (data$kind != 58))
      non_icmpv6_traffic[seed, protocol_index] <- mean(get_traffic_per_node(non_icmpv6))
    }
  }
  traffic <- matrix(nrow = 4, ncol = length(protocols))
  for(protocol_index in seq(length(protocols))) {
    traffic[1, protocol_index] <- mean(akes_traffic[, protocol_index])
    traffic[2, protocol_index] <- mean(non_akes_traffic[, protocol_index])
    traffic[3, protocol_index] <- mean(icmpv6_traffic[, protocol_index])
    traffic[4, protocol_index] <- mean(non_icmpv6_traffic[, protocol_index])
  }

  cairo_pdf(file = paste("traffic-", experiment, ".pdf", sep = ""), width = 12, height = 2.8)
  par(cex = 1)
  par(las = 1)
  par(mar = c(4.1, 4.1 + 9.5, 0.2, 0.5))
  barplot(traffic/1000,
          names = protocol_labels,
          col = topo.colors(4),
          horiz = TRUE,
          xlim = c(0, 50),
          xlab = "mean outgoing traffic per node (in kB)",
          legend.text = c("AKES' MAC command frames", "SMOR's MAC command frames", "ICMPv6 messages", "UDP datagrams"))
  dev.off()

  # energy
  protocols <- c(protocols, "null")
  protocol_labels <- c(protocol_labels, "No routing protocol")
  e <- matrix(nrow = 2, ncol = length(protocols))
  energy_means <- c()
  for(protocol_index in seq(length(protocols))) {
    rx <- c()
    tx <- c()
    for(seed in seeds) {
      file <- paste(getwd(), "/", experiment, "/E/", protocols[protocol_index], "-", seed, ".csv", sep = "")
      data <- read.table(file, header = T, sep = ",")
      rx <- c(rx, mean(data$rx))
      tx <- c(tx, mean(data$tx))
    }
    e[1, protocol_index] <- (mean(rx) / 1000000) * 20
    e[2, protocol_index] <- (mean(tx) / 1000000) * 24
    energy_means <- c(energy_means, sum(e[, protocol_index]))
  }

  pdf(file = paste("energy-", experiment, ".pdf", sep = ""), width = 12, height = 2.8)
  par(cex = 1)
  par(las = 1)
  par(mar = c(4.1, 4.1 + 9.5, 0.2, 0.1 + 1.2))
  centers <- barplot(e,
                     names = protocol_labels,
                     horiz = TRUE,
                     xlim = c(0, 1200),
                     xlab = "mean consumed charge per node (in mAs)",
                     legend.text=c("Receiving (20mA)", "Transmitting (24mA)"))
  for(i in seq(length(protocols))) {
    s <- sum(e[, i])
    text(s + 45, centers[i], format(round(s, 2), nsmall = 2))
  }
  dev.off()
}
