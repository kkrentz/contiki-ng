library(svglite)

experiments <- c(
  "csl-classic-ml-sleepless",
  "csl-classic-ml",
  "csl-classic-blind",
  "orchestra"
  )
experiment_labels <- c(
  "HPI-MAC\n(32 Hz/\nML-based)",
  "HPI-MAC\n(8 Hz/\nML-based)",
  "HPI-MAC\n(8 Hz/\nblind)",
  "ALICE"
  )
rates <- c(25, 50, 100, 200, 400)

# set colors
rate_colors <- c("darkred", "red", "orange", "green", "darkgreen")
rate_colors <- rate_colors[1:length(rates)]

# from https://groups.google.com/g/r-help-archive/c/Y2x_YAJUf8Y
mybarplot <-
  function (height, width = 1, space = NULL, names.arg = NULL,
            legend.text = NULL, beside = FALSE, horiz = FALSE, density = NULL,
            angle = 45, col = NULL, border = par("fg"), main = NULL,
            sub = NULL, xlab = NULL, ylab = NULL, xlim = NULL, ylim = NULL,
            xpd = TRUE, log = "", axes = TRUE, axisnames = TRUE, cex.axis =
              par("cex.axis"),
            cex.names = par("cex.axis"), inside = TRUE, plot = TRUE,
            axis.lty = 0, offset = 0, add = FALSE, args.legend = NULL,
            ...)
  {
    if (!missing(inside))
      .NotYetUsed("inside", error = FALSE)
    if (is.null(space))
      space <- if (is.matrix(height) && beside)
        c(0, 1)
    else 0.2
    space <- space * mean(width)
    if (plot && axisnames && is.null(names.arg))
      names.arg <- if (is.matrix(height))
        colnames(height)
    else names(height)
    if (is.vector(height) || (is.array(height) && (length(dim(height)) ==
                                                   1))) {
      height <- cbind(height)
      beside <- TRUE
      if (is.null(col))
        col <- "grey"
    }
    else if (is.matrix(height)) {
      if (is.null(col))
        col <- grey.colors(nrow(height))
    }
    else stop("'height' must be a vector or a matrix")
    if (is.logical(legend.text))
      legend.text <- if (legend.text && is.matrix(height))
        rownames(height)
    stopifnot(is.character(log))
    logx <- logy <- FALSE
    if (log != "") {
      logx <- length(grep("x", log)) > 0L
      logy <- length(grep("y", log)) > 0L
    }
    if ((logx || logy) && !is.null(density))
      stop("Cannot use shading lines in bars when log scale is used")
    NR <- nrow(height)
    NC <- ncol(height)
    if (beside) {
      if (length(space) == 2)
        space <- rep.int(c(space[2L], rep.int(space[1L],
                                              NR - 1)), NC)
      width <- rep(width, length.out = NR)
    }
    else {
      width <- rep(width, length.out = NC)
    }
    offset <- rep(as.vector(offset), length.out = length(width))
    delta <- width/2
    w.r <- cumsum(space + width)
    w.m <- w.r - delta
    w.l <- w.m - delta
    log.dat <- (logx && horiz) || (logy && !horiz)
    if (log.dat) {
      if (min(height + offset, na.rm = TRUE) <= 0)
        stop("log scale error: at least one 'height + offset' value <= 0")
      if (logx && !is.null(xlim) && min(xlim) <= 0)
        stop("log scale error: 'xlim' <= 0")
      if (logy && !is.null(ylim) && min(ylim) <= 0)
        stop("log scale error: 'ylim' <= 0")
      rectbase <- if (logy && !horiz && !is.null(ylim))
        ylim[1L]
      else if (logx && horiz && !is.null(xlim))
        xlim[1L]
      else 0.9 * min(height, na.rm = TRUE)
    }
    else rectbase <- 0
    if (!beside)
      height <- rbind(rectbase, apply(height, 2L, cumsum))
    rAdj <- offset + (if (log.dat)
      0.9 * height
      else -0.01 * height)
    delta <- width/2
    w.r <- cumsum(space + width)
    w.m <- w.r - delta
    w.l <- w.m - delta
    if (horiz) {
      if (is.null(xlim))
        xlim <- range(rAdj, height + offset, na.rm = TRUE)
      if (is.null(ylim))
        ylim <- c(min(w.l), max(w.r))
    }
    else {
      if (is.null(xlim))
        xlim <- c(min(w.l), max(w.r))
      if (is.null(ylim))
        ylim <- range(rAdj, height + offset, na.rm = TRUE)
    }
    if (beside)
      w.m <- matrix(w.m, ncol = NC)
    if (plot) {
      opar <- if (horiz)
        par(xaxs = "i", xpd = xpd)
      else par(yaxs = "i", xpd = xpd)
      on.exit(par(opar))
      if (!add) {
        plot.new()
        plot.window(xlim, ylim, log = log, ...)
      }
      xyrect <- function(x1, y1, x2, y2, horizontal = TRUE,
                         ...) {
        if (horizontal)
          rect(x1, y1, x2, y2, ...)
        else rect(y1, x1, y2, x2, ...)
      }
      if (beside)
        xyrect(rectbase + offset, w.l, c(height) + offset,
               w.r, horizontal = horiz, angle = angle, density = density,
               col = col, border = border)
      else {
        for (i in 1L:NC) {
          xyrect(height[1L:NR, i] + offset[i], w.l[i],
                 height[-1, i] + offset[i], w.r[i], horizontal = horiz,
                 angle = angle, density = density, col = col,
                 border = border[ifelse(i > length(border), 1, i)])
          ######## Line edited
        }
      }
      if (axisnames && !is.null(names.arg)) {
        at.l <- if (length(names.arg) != length(w.m)) {
          if (length(names.arg) == NC)
            colMeans(w.m)
          else stop("incorrect number of names")
        }
        else w.m
        axis(if (horiz)
          2
          else 1, at = at.l, labels = names.arg, lty = axis.lty,
          cex.axis = cex.names, ...)
      }
      if (!is.null(legend.text)) {
        legend.col <- rep(col, length.out = length(legend.text))
        if ((horiz & beside) || (!horiz & !beside)) {
          legend.text <- rev(legend.text)
          legend.col <- rev(legend.col)
          density <- rev(density)
          angle <- rev(angle)
        }
        xy <- par("usr")
        if (is.null(args.legend)) {
          legend(xy[2L] - xinch(0.1), xy[4L] - yinch(0.1),
                 legend = legend.text, angle = angle, density = density,
                 fill = legend.col, xjust = 1, yjust = 1)
        }
        else {
          args.legend1 <- list(x = xy[2L] - xinch(0.1),
                               y = xy[4L] - yinch(0.1), legend = legend.text,
                               angle = angle, density = density, fill = legend.col,
                               xjust = 1, yjust = 1)
          args.legend1[names(args.legend)] <- args.legend
          do.call("legend", args.legend1)
        }
      }
      title(main = main, sub = sub, xlab = xlab, ylab = ylab,
            ...)
      if (axes)
        axis(if (horiz)
          1
          else 2, cex.axis = cex.axis, ...)
      invisible(w.m)
    }
    else w.m
  }

# maps the name of an OpenMote-B in Strasbourg to its ID
name_to_id <- function(name) {
  if (startsWith(name, "cooja-")) {
    as.numeric(sub("cooja-", "", name))
  } else {
    as.numeric(sub("openmoteb-", "", name))
  }
}

# maps the address of an OpenMote-B on the Strasbourg site to its ID
address_to_id <- function(address) {
  mapping <- c(
    "68e5" = 1,
    "6988" = 2,
    "6910" = 3,
    "68c6" = 4,
    "6981" = 5,
    "696c" = 6,
    # 7 and 8 are out of order
    "691b" = 9,
    "6971" = 10,
    "6e71" = 11,
    "695f" = 12,
    "695c" = 13,
    "6df1" = 14,
    "6932" = 15,
    "692f" = 16,
    "6dba" = 17,
    "698e" = 18, # does not have a reliable serial output
    "6904" = 19,
    "697a" = 20, # does not have a reliable serial output
    "694d" = 21,
    "692e" = 22,
    "68f7" = 23,
    "6949" = 24,
    "6dd0" = 25,
    "6960" = 26,
    "68e7" = 27,
    "68c4" = 28,
    "6921" = 29,
    "6e63" = 30,
    "68d1" = 31,
    "692b" = 32,
    "6964" = 33,
    "6973" = 34,
    "6e8f" = 35,
    "6dc2" = 36,
    "68b8" = 37,
    "694a" = 38,
    "68f0" = 39, # out of order
    "68a0" = 40
  )
  key <- sub("^0x", "", tolower(address))
  ifelse(startsWith(address, "00"), strtoi(paste0("0x", address)), unname(mapping[key]))
}

# determine transmission rates
txrates <- c()
for (rate in rates) {
  txrates <- c(txrates, paste(round(rate / 10, 1), "s"))
}

# determine ids
data <- read.table(paste(experiments[1], "-", rates[1], ".csv", sep=""), header = T, sep = ";")
sent_datagrams <- subset(data, event == "s")
ids <- c()
for (address in sent_datagrams$address) {
  ids <- c(ids, address_to_id(address))
}
ids <- ids[!duplicated(ids)]
ids <- sort(ids)

# plot delivery ratios
delivery_ratios <- matrix(nrow = length(rates), ncol = length(experiments))
confidences <- matrix(nrow = length(rates), ncol = length(experiments))
for (rate_index in 1:length(rates)) {
  for (experiment_index in 1:length(experiments)) {
    data <- read.table(paste(experiments[experiment_index], "-", rates[rate_index], ".csv", sep=""), header = T, sep = ";")
    per_node_delivery_ratios <- setNames(numeric(length(ids)), ids)
    all_received_datagrams <- c()
    for (id in ids) {
      received_datagrams <- subset(data, (event == "r") & (address_to_id(address) == id))
      sent_datagrams <- subset(data, (event == "s") & (address_to_id(address) == id))
      received_datagrams <- sent_datagrams$counter %in% received_datagrams$counter
      all_received_datagrams <- c(all_received_datagrams, received_datagrams)
      received_datagrams_count <- sum(received_datagrams == TRUE)
      sent_datagrams_count <- length(sent_datagrams$counter)
      per_node_delivery_ratios[toString(id)] = received_datagrams_count / sent_datagrams_count
    }
    delivery_ratios[rate_index, experiment_index] <- mean(per_node_delivery_ratios) * 100
    confidences[rate_index, experiment_index] <- (1.96/sqrt(length(all_received_datagrams))) * sd(all_received_datagrams * 100)
    svglite(file = paste0(experiments[experiment_index], "-", rates[rate_index], ".svg"), width = 12, height = 6)
    barplot(per_node_delivery_ratios)
    dev.off()
  }
}

svglite(file="pdrs.svg", width=6.2, height=length(experiments), bg = "transparent")
par(cex = 1)
par(las = 1)
par(mar = c(5.1-1.1, 4.1+0.9, 4.1-4.1, 2.1-2.1))
centers <- barplot(delivery_ratios,
                   beside = TRUE,
                   names = experiment_labels,
                   col = rate_colors,
                   horiz = TRUE,
                   xlab = "mean delivery ratio in %",
                   xaxt = "n",
                   xlim = c(0, 170))
axis(1, cex.axis = 1, at = seq(0.0,100,20))
for(i in seq(length(delivery_ratios))) {
  text(delivery_ratios[i] + 1, centers[i], paste0("\u2300 ",
                                                  format(round(delivery_ratios[i], 1), nsmall = 1),
                                                  "%",
                                                  " \u00b1 ",
                                                  format(round(confidences[i], digits = 1), nsmall = 1),
                                                  "%"), adj = c(0,0.4), cex=0.9)
}
legend("topright",
       rev(txrates),
       col = rev(rate_colors),
       pch = 15,
       title = expression(bar(T)))
dev.off()

# plot delays
delays <- list()
maxima <- c()
means <- c()
confidences <- matrix(nrow = length(rates), ncol = length(experiments))
i <- 0
for (experiment_index in 1:length(experiments)) {
  for (rate_index in 1:length(rates)) {
    data <- read.table(paste(experiments[experiment_index], "-", rates[rate_index], ".csv", sep=""), header = T, sep = ";")
    per_experiment_delays <- c()
    all_delays <- c()
    for (id in ids) {
      received_datagrams <- subset(data, (event == "r") & (address_to_id(address) == id))
      # remove duplicate receptions
      for(c in received_datagrams$counter) {
        rows <- which(received_datagrams$counter == c)
        if(length(rows) > 1) {
          rows_to_delete <- tail(rows, n = (length(rows) - 1))
          received_datagrams <- received_datagrams[-rows_to_delete,]
        }
      }
      sent_datagrams <- subset(data, (event == "s") & (address_to_id(address) == id))
      for (c in received_datagrams$counter) {
        delay <- received_datagrams[which(received_datagrams$counter == c),]$t - sent_datagrams[which(sent_datagrams$counter == c),]$t
        per_experiment_delays <- c(per_experiment_delays, delay)
        all_delays <- c(all_delays, delay)
      }
    }
    i <- i + 1
    delays[[i]] <- per_experiment_delays
    maxima <- c(maxima, max(per_experiment_delays))
    means <- c(means, mean(per_experiment_delays))
    confidences[rate_index, experiment_index] <- (1.96/sqrt(length(all_delays))) * sd(all_delays)
  }
}

at_vector <- c()
at_vector_centers <- c()
i <- 0
for (experiment in experiments) {
  is <- c()
  for (rate in rates) {
    i <- i + 1
    is <- c(is, i)
    at_vector <- c(at_vector, i)
  }
  at_vector_centers <- c(at_vector_centers, mean(is))
  i <- i + 1
}

svglite(file="delays.svg", width=6.2, height=length(experiments), bg = "transparent")
par(cex = 1)
par(las = 1)
par(mar = c(5.1-1.1, 4.1+0.9, 4.1-4.1, 2.1-2.1))
boxplot(delays,
        border = rate_colors,
        xlab = "delay (in s)",
        yaxt = "n",
        ylim = c(0, max(maxima) + 18),
        at = at_vector,
        horizontal = TRUE)
axis(2, cex.axis = 1, at = at_vector_centers, labels=experiment_labels)
legend("topright",
       rev(txrates),
       col = rev(rate_colors),
       pch = 15,
       title = expression(bar(T)))
i <- 0
j <- 0
for (at_vector_index in 1:length(at_vector)) {
  text(maxima[at_vector_index] + 0.8, at_vector[at_vector_index], paste("\u2300",
                                                        format(round(means[at_vector_index], 1), nsmall = 1),
                                                        "s",
                                                        "\u00b1",
                                                        format(round(confidences[at_vector_index]*1000, 0), nsmall = 0),
                                                        "ms"), adj = c(0,0.5), cex=0.9)
}
dev.off()

# plot energy
e <- matrix(nrow = 2, ncol = length(rates) * length(experiments))
c_constant <- 1.96/sqrt(length(ids)) # 95% confidence interval
confidences <- matrix(nrow = length(rates), ncol = length(experiments))
i <- 0
for (experiment_index in 1:length(experiments)) {
  for (rate_index in 1:length(rates)) {
    data <- read.table(paste(experiments[experiment_index], "-", rates[rate_index], "-energy.csv", sep=""), header = T, sep = ";")
    i <- i + 1
    rx_percentages <- c()
    tx_percentages <- c()
    for (row in 1:length(data$rx)) {
      rx_percentages <- c(rx_percentages, data$rx[row] / data$total[row] * 100)
      tx_percentages <- c(tx_percentages, data$tx[row] / data$total[row] * 100)
    }
    e[1, i] <- mean(rx_percentages)
    e[2, i] <- mean(tx_percentages)
    duty_cycles <- rx_percentages + tx_percentages
    confidences[i] <- c_constant * sd(duty_cycles)
  }
}

svglite(file="energy.svg", width=6.2, height=length(experiments), bg = "transparent")
par(cex = 1)
par(las = 1)
par(mar = c(5.1-1.1, 4.1+0.9, 4.1-4.1, 2.1-2.1))
centers <- mybarplot(e,
                     border = rep(rate_colors, length(experiments)),
                     horiz = TRUE,
                     space = rep(c(1, rep(0.25, length(rates) - 1)), length(experiments)),
                     xlab = "mean duty cycle per node (in %)",
                     xlim = c(0, 14),
                     xaxt = "n",
                     legend.text=c("Receiving", "Transmitting"),
                     args.legend=list(x="bottomright"))
axis(1, cex.axis = 1, at = seq(0,10,1))
i <- 0
for (experiment_index in 1:length(experiments)) {
  for (rate_index in 1:length(rates)) {
    i <- i + 1
    text(e[1, i] + e[2, i] + 0.1, centers[i], paste0("\u2300 ",
                                                     format(round(e[1, i] + e[2, i], 1), nsmall = 1),
                                                     "%",
                                                     " \u00b1 ",
                                                     format(round(confidences[i], digits = 1)), "%"), adj = c(0,0.5))
  }
}
mids <-c()
i <- 0
for (experiment in experiments) {
  sum <- 0
  for (rate in rates) {
    i <- i + 1
    sum <- sum + centers[i]
  }
  mids <- c(mids, sum / length(rates))
}
axis(2, cex.axis = 1, at = mids, labels=experiment_labels, lwd=0)
l <- legend("topright",
       rev(txrates),
       col = rev(rate_colors),
       pch = 15,
       title = expression(bar(T)))
dev.off()

# percentual improvements
if ((length(experiments) == 4) && (experiments[2] == "csl-classic-ml") && (experiments[4] == "orchestra")) {
  hpi_mac_indices <- 1:length(rates) + length(rates) * 1
  orchestra_indices <- 1:length(rates) + (length(rates) * (length(experiments) - 1))

  print("increases of duty cycles")
  e_hpi_mac <- e[,hpi_mac_indices]
  e_orchestra <- e[,orchestra_indices]
  for(rate_index in 1:length(rates)) {
    duty_cycle_hpi_mac <- e_hpi_mac[1,rate_index] + e_hpi_mac[2,rate_index]
    duty_cycle_orchestra <- e_orchestra[1,rate_index] + e_hpi_mac[2,rate_index]
    print(((duty_cycle_hpi_mac - duty_cycle_orchestra)/duty_cycle_orchestra) * 100)
  }
}
