# -*- Makefile -*-

ACLOCAL_AMFLAGS  = -I m4
SUBDIRS          = extensions extensions/ACCOUNT extensions/pknock

bin_SCRIPTS = geoip/xt_geoip_query
pkglibexec_SCRIPTS = asn/xt_asn_build asn/xt_asn_dl asn/xt_asn_fetch \
	geoip/xt_geoip_build geoip/xt_geoip_build_maxmind \
	geoip/xt_geoip_dl geoip/xt_geoip_dl_maxmind
man_MANS = xtables-addons.8 asn/xt_asn_build.1 asn/xt_asn_dl.1 \
	geoip/xt_geoip_build.1 geoip/xt_geoip_dl.1 \
	geoip/xt_geoip_build_maxmind.1 geoip/xt_geoip_dl_maxmind.1 \
	geoip/xt_geoip_query.1

.PHONY: FORCE
FORCE:

xtables-addons.8: FORCE
	${MAKE} -f Makefile.mans all;

clean-local-mans:
	${MAKE} -f Makefile.mans clean;

clean-local: clean-local-mans

config.status: Makefile.iptrules.in

.PHONY: tarball
tarball:
# do not use mkdir_p here.
	tmpdir=$$(mktemp -dtu); \
	mkdir $$tmpdir; \
	(cd ${top_srcdir} && git archive --prefix=${PACKAGE_NAME}-${PACKAGE_VERSION}/ HEAD | tar -C $$tmpdir -x); \
	(cd $$tmpdir/${PACKAGE_NAME}-${PACKAGE_VERSION} && autoreconf -fi && rm -Rf autom4te*.cache); \
	tar --use=xz -C $$tmpdir -cf ${PACKAGE_NAME}-${PACKAGE_VERSION}.tar.xz --owner=root --group=root ${PACKAGE_NAME}-${PACKAGE_VERSION}/; \
	rm -Rf $$tmpdir
