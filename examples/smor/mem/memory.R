library(svglite)

protocol_labels <- c(
  "SMOR",
  "RPL (non-storing)",
  "RPL (storing)"
)

# NULL
#   text	   data	    bss	    dec	    hex	filename
#45646	    502	  17754	  63902	   f99e	client.openmote
null_rom <- 45646 + 502
null_ram <- 502 + 17754

# SMOR
#   text	   data	    bss	    dec	    hex	filename
#50213	    526	  18610	  69349	  10ee5	client.openmote
smor_rom <- 50213 + 526 - null_rom
smor_ram <- 526 + 18610 - null_ram

# RPL (non-storing)
#   text	   data	    bss	    dec	    hex	filename
#54875	    618	  18738	  74231	  121f7	client.openmote
rpl_non_rom <- 54875 + 618 - null_rom
rpl_non_ram <- 618 + 18738- null_ram

# RPL (storing)
#   text	   data	    bss	    dec	    hex	filename
#56566	    651	  19222	  76439	  12a97	client.openmote
rpl_rom <- 56566 + 651 - null_rom
rpl_ram <- 651 + 19222- null_ram

ram <- c(smor_ram, rpl_non_ram, rpl_ram)
rom <- c(smor_rom, rpl_non_rom, rpl_rom)

cairo_pdf(file = "rom.pdf", width=5.7, height=1.6)
par(cex=1)
par(las=1)
par(mar=c(4.1, 4.1+4, 0.2, 0.1+1))
barplot(rom/1000,
        horiz = TRUE,
        xlab = "program memory (in kB)",
        xlim = c(0, 12),
        names = protocol_labels)
dev.off()

cairo_pdf(file = "ram.pdf", width=5.7, height=1.6)
par(cex=1)
par(las=1)
par(mar=c(4.1, 4.1+4, 0.2, 0.1+1))
barplot(ram,
        horiz = TRUE,
        xlab = "RAM allocation (in bytes)",
        xlim = c(0, 2000),
        names = protocol_labels)
dev.off()