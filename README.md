IETF and IEEE protocols for low-power power and lossy networks (LLNs) lack critical security features. They fall short of compromise resilience, denial-of-sleep resilience, and/or strong freshness. Therefore, this fork focuses on implementing a security-enhanced protocol stack for LLNs.

| Layer                 | Protocol(s)                                                                                         |
| :---                  | :---                                                                                                |
| Application           | CoAP, [OSCORE-NG](https://github.com/kkrentz/libcoap), TRAP                                         |
| Transport             | UDP                                                                                                 |
| Network               | IPv6                                                                                                |
| Adaption              | 6LoWPAN (in mesh-under mode)                                                                        |
| Medium access control | [CSL](#csl-coordinated-sampled-listening), [SMOR](#smor-secure-multipath-opportunistic-routing)     |
| Physical              | IEEE 802.15.4                                                                                       |

# CSL: Coordinated Sampled Listening

CSL is a standardized MAC protocol for IEEE 802.15.4 networks. Its rationale is to send a stream of wake-up frames prior to an actual payload frame. Each wake-up frame essentially contains the time when the transmission of the payload frame will begin. This hint enables the receiver of a wake-up frame to sleep until the transmission of the payload frame is about to begin.

## Configuration

There are two main ways to use our CSL implementation. First, it is possible to adhere to the IEEE 802.15.4 standard. However, due to security vulnerabilities (even when enabling IEEE 802.15.4 security), this configuration is only meant for testing and research purposes. Second, it is possible to enable additional security measures.

### IEEE 802.15.4-Compliant CSL

For the standards-compliant configuration, add the following line to your `project-conf.h`
```c
/* auto-configures the MAC layer */
#include "net/mac/csl/csl-autoconf.inc"
```

Finally, in your Makefile, insert:
```
MAKE_MAC = MAKE_MAC_CSL
```

### Hasso Plattner Institute MAC (HPI-MAC)

For the secure configuration, aka HPI-MAC, add the following two lines to your `project-conf.h`:
```c
#define CSL_CONF_COMPLIANT 0
#include "net/mac/csl/csl-autoconf.inc"
```
and the following lines to your Makefile:
```c
MAKE_MAC = MAKE_MAC_CSL
MODULES += os/services/akes
```

For better reliability (at the cost of higher latencies), enable ML-based channel hopping:
```c
#define CSL_CHANNEL_SELECTOR_CONF_WITH_D_UCB 1
```
By default, blind channel hopping is used. Note, however, that ML-based channel hopping consumes a considerable amount of RAM.

### Troubleshooting

Two parameters might need to be adapted to your radio environment:

```c
/* If the CCA threshold is too low, IEEE 802.15.4 nodes may end up sending never. */
#define CSL_CONF_CCA_THRESHOLD (-70) /* dBm */
/* The output power controls the communication range. */
#define CSL_CONF_OUTPUT_POWER (0) /* dBm */
```

Besides, I observed an abnormally many collisions when using a laptop and a USB hub. It seems that OpenMotes do not get enough current in this scenario. To fix this, either plug in the power cable of your laptop or connect your OpenMotes without a USB hub.

## Features

HPI-MAC features:
- Low base energy consumption, e.g., 0.5% duty cycle when waking up eight times per second
- Low energy consumption at the sender side by learning the wake-up times of neighboring nodes, as well as the clock drifts compared to neighboring nodes
- Burst forwarding for better throughput
- ML-based channel hopping and acknowledged broadcast frames for higher reliability
- High MAC layer security
  - Authentication and encryption of frames via pairwise session keys
  - Strong freshness, i.e., even delayed frames are recognized as replayed
  - Denial-of-sleep-resilient medium access control
  - Denial-of-sleep-resilient pairwise session key establishment

## Code structure

- [os/services/akes](https://github.com/kkrentz/contiki-ng/tree/master/os/services/akes)
  - Contains the adaptive key establishment scheme (AKES)
- [os/net/mac/csl](https://github.com/kkrentz/contiki-ng/tree/master/os/net/mac/csl)
  - Contains the CSL MAC protocol

## Supported Platforms

- CC2538-based platforms
- [Cooja](https://github.com/kkrentz/cooja) motes

## TODOs

- Support newer platforms, such as CC13x4/CC26x4
- Currently, this CSL implementation is limited to `macCslInterval=0`. This is to obviate data request frames and to minimize the duration of periodic wake ups. However, some platforms do not support `macCslInterval=0`. Support for `macCslInterval!=0` is hence desirable. For securing data request frames, we may echo truncated OTP bits
- Autoconfigure CCA threshold
- Autoconfigure output power
- Disable or accelerate wake ups on mains-powered devices, such as border routers

## Further Reading
- [IEEE 802.15.4-compliant CSL](https://standards.ieee.org/ieee/802.15.4/11041/)
- [HPI-MAC](https://doi.org/10.25932/publishup-43930)
- [ML-based Channel Hopping](https://doi.org/10.1007/978-3-030-98978-1_3)

# SMOR: Secure Multipath Opportunistic Routing

Many state-of-the-art IoT technologies, such as Thread or Wi-SUN, employ the Routing Protocol for Low-Power and Lossy Networks (RPL), which is particularly vulnerable to compromised nodes. SMOR, by contrast, tolerates compromises of single nodes. Also, SMOR improves on RPL’s delays and packet delivery ratios.

## Comparison of SMOR with Requests for Comments (RFCs)

| Feature                                | RPL                | AODV               | DSR                | SMOR               |
| :---                                   | :---:              | :---:              | :---:              | :---:              |
| Tolerance of node failures             | :white_circle:¹    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Migration to better links              | :white_circle:²    | :x:                | :x:                | :white_check_mark: |
| Economy of broadcasts                  | :white_check_mark: | :x:                | :x:                | :white_check_mark: |
| Support for point-to-point traffic     | :white_circle:³    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Resilience to node compromises         | :x:                | :x:                | :x:                | :white_check_mark: |

¹ Failures of root nodes prevent network formation

² As RPL does not assess unused links, it may miss opportunities to migrate to better links

³ IPv6 packets may take detours via a root node or a common ancestor

## Further Reading

- [Paper](https://doi.org/10.1016/j.comcom.2024.01.024)
