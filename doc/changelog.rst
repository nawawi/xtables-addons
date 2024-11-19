v3.27 (2024-11-19)
==================

* Support for Linux 6.12
* xt_DNETMAP: cure crash on netns shutdown


v3.26 (2024-03-22)
==================

* xt_pknock: fix misuse of shash API
* xt_SYSRQ: resolve crash, switch to new SHASH_ON_STACK


v3.25 (2023-08-18)
==================

* xt_ipp2p: change text-search algo to KMP
  (fix some false negative matches)


v3.24 (2023-04-30)
==================

* xt_geoip: bump number of territories per rule
* geoip: use stdout for output and stderr for errors/diag


v3.23 (2023-01-12)
==================

* Support for Linux 6.2


v3.22 (2022-10-25)
==================

* Support for up to Linux 6.1


v3.21 (2022-06-13)
==================

* xt_ECHO: support flowi6_to_flowi_common starting Linux 5.10.121


v3.20 (2022-04-10)
==================

* Support for Linux 5.17


v3.19 (2022-02-01)
==================

* bumped minimum supported kernel version from 4.15 to 4.16
* xt_condition: make mutex per-net
* xt_ipp2p: add IPv6 support
* xt_ECHO, xt_TARPIT: do not build IPv6 parts if kernel has
  IPv6 build-time disabled


v3.18 (2021-03-11)
==================

* xt_pknock: fix a build failure on ARM 32-bit


v3.17 (2021-02-28)
==================

* xt_pknock: cure a NULL deref


v3.16 (2021-02-24)
==================

* xt_pknock: build fix for ILP32 targets


v3.15 (2021-02-05)
==================

* xt_ECHO: support new function signature of security_skb_classify_flow
* xt_lscan: add --mirai option
* Support for Linux 5.11


v3.14 (2020-11-24)
==================

* DELUDE, ECHO, TARPIT: use actual tunnel socket (ip_route_me_harder).
* geoip: scripts for use with MaxMind DB have been brought back,
  partly under new names.
* Gave xt_geoip_fetch a more fitting name, xt_geoip_query.


v3.13 (2020-11-20)
==================

* Support for Linux 4.19.158 and 5.4.78 (ip_route_me_harder)


v3.12 (2020-11-19)
==================

* Support for Linux 5.10 and 5.9.9 API
  (changes to ip_route_me_harder there)


v3.11 (2020-09-06)
==================

* Support for up to Linux 5.9


v3.10 (2020-07-28)
==================

* Support for up to Linux 5.8


v3.9 (2020-02-25)
=================

* Support for Linux 5.6 procfs changes


v3.8 (2020-02-03)
=================

* Support for Linux 5.5
* xt_geoip_build now expects the DBIP format as input,
  Maxmind is thrown out.


v3.7 (2019-12-01)
=================

Fixes:

* xt_geoip: fix in6_addr little-endian byte swapping


v3.6 (2019-11-20)
=================

Enhancements:

* support for up to Linux 5.4


v3.5 (2019-09-10)
=================

Enhancements:

* xt_DELUDE, xt_TARPIT: added additional code needed to work with
  bridges from Linux 5.0 onwards.


v3.4 (2019-09-06)
=================

Enhancements:

* support for up to Linux 5.3
* xt_PROTO module


v3.3 (2019-03-07)
=================

Enhancements:

* support for Linux 5.0


v3.2 (2018-09-07)
=================

Changes:

* rework xt_geoip_build to scan the immediate directory for .csv,
  not to scan for GeoLite2-Country-CSV_\d+.


v3.1 (2018-08-14)
=================

Enhancements:

* support for Linux 4.17, 4.18


v3.0 (2018-02-12)
=================

Enhancements:

* support for Linux 4.15, 4.16

Changes:

* remove support for Linux 3.7--4.14

If you want to use Xtables-addons with kernels older than 4.15,
use the addons 2.x series.
