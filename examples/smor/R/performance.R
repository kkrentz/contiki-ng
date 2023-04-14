get_traffic_per_node <- function(d, number_of_nodes = 5) {
  traffic_per_node <- vector(length = number_of_nodes)
  for(node_id in seq(number_of_nodes)) {
    subdata <- subset(d, d$node == node_id)
    traffic_per_node[node_id] <- sum(subdata$length)
  }
  return (traffic_per_node)
}

print_percentual_improvements <- function(means, rpl_indices = 1:4, smor_indices = 5:7) {
  rpl_min <- min(means[rpl_indices])
  rpl_max <- max(means[rpl_indices])
  smor_min <- min(means[smor_indices])
  smor_max <- max(means[smor_indices])
  print((rpl_max - smor_min) * 100 / rpl_max)
  print((rpl_min - smor_max) * 100 / rpl_min)
}

seeds <- seq(2000)
max_datagram <- 300
for(experiment in c("stable", "weak")) {
  protocols <- c("rpl-classic-p2p",
                 "rpl-classic",
                 "rpl-p2p",
                 "rpl",
                 "smor-very-agile",
                 "smor-more-agile",
                 "smor")
  protocol_labels <- c("RPL (storing/Node 3 as root)",
                       "RPL (storing/Node 1 as root)",
                       "RPL (non-storing/Node 3 as root)",
                       "RPL (non-storing/Node 1 as root)",
                       expression(paste("SMOR (", epsilon, "=20%)")),
                       expression(paste("SMOR (", epsilon, "=10%)")),
                       expression(paste("SMOR (", epsilon, "=1%)")))

  # delivery ratios
  delivery_ratios <- matrix(nrow = length(seeds), ncol = length(protocols))
  for(protocol_index in seq(length(protocols))) {
    for(seed in seeds) {
      file <- paste(getwd(), "/", experiment, "/D/", protocols[protocol_index], "-", seed, ".csv", sep = "")
      data <- read.table(file, header = T, sep = ",")
      data <- subset(data, datagram <= max_datagram)
      received_datagrams <- 1:max_datagram %in% data$datagram
      received_datagrams_count <- sum(received_datagrams == TRUE)
      delivery_ratios[seed, protocol_index] <- received_datagrams_count * 100 / max_datagram
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

  print("range of percentual PDR improvement")
  print_percentual_improvements(delivery_ratio_means)
  
  # forwarders
  forwarder_usage_means <- matrix(nrow = 3, ncol = length(protocols))
  for(protocol_index in seq(length(protocols))) {
    for(f in c(3, 4, 5)) {
      forwarder_usages <- vector(length = length(seeds))
      for(seed in seeds) {
        file <- paste(getwd(), "/", experiment, "/D/", protocols[protocol_index], "-", seed, ".csv", sep ="")
        data <- read.table(file, header = T, sep = ",")
        data <- subset(data, datagram <= max_datagram)
        data <- subset(data, forwarder == f)
        forwarder_usages[seed] <- length(data$forwarder)
      }
      forwarder_usage_means[f - 2, protocol_index] <- mean(forwarder_usages)
    }
  }
  cairo_pdf(file = paste("forwarders-", experiment, ".pdf", sep = ""), width = 7, height = 2.8)
  par(cex = 1)
  par(las = 1)
  par(mar = c(4.1, 4.1 + 9.5, 0.2, 0.1 + 1.2))
  centers <- barplot(forwarder_usage_means,
                     names = protocol_labels,
                     col = rainbow(3),
                     horiz = TRUE,
                     xlim = c(0,500),
                     xlab = "mean forwarder usage per run (ignoring duplicates)",
                     legend.text=c("Node 3", "Node 4", "Node 5"))
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
      rpl_classic_p2p_delays <- delays,
      rpl_classic_delays <- delays,
      rpl_p2p_delays <- delays,
      rpl_delays <- delays,
      smor_very_agile_delays <- delays,
      smor_more_agile_delays <- delays,
      smor_delays <- delays,
    )
    delay_means <- c(delay_means, mean(delays))
  }
  
  png(file = paste("delays-", experiment, ".png", sep = ""), width = 12, height = 2.8, units="in",res=72)
  par(cex = 1)
  par(las = 1)
  par(mar = c(4.1, 4.1 + 9.5, 0.2, 0.1))
  boxplot(
    rpl_classic_p2p_delays,
    rpl_classic_delays,
    rpl_p2p_delays,
    rpl_delays,
    smor_very_agile_delays,
    smor_more_agile_delays,
    smor_delays,
    names = protocol_labels,
    ylim = c(0,14.2),
    xaxt = "n",
    xlab = "delay (in s)",
    horizontal = TRUE)
  axis(1, cex.axis = 1.2, at = seq(0.0,14.2,1))
  dev.off()
  
  print("range of percentual delay improvement")
  print_percentual_improvements(delay_means)

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

  print("range of percentual energy overhead")
  energy_means <- c()
  for(i in seq(length(protocols) - 1)) {
    energy_means <- c(energy_means, sum(e[, i]))
  }
  print_percentual_improvements(energy_means)
}
