AUTOMAKE_OPTIONS=1.6

DOC_MODULE=libaccountsservice

DOC_MAIN_SGML_FILE=libaccountsservice-docs.xml

DOC_SOURCE_DIR=$(top_srcdir)/src/libaccountsservice

MKBD_OPTIONS=--xml-mode --output-format=xml --name-space=act

HFILE_GLOB=$(top_srcdir)/src/libaccountsservice/*.h

IGNORE_HFILES= \
	accounts-generated.h \
	accounts-user-generated.h \
	ck-manager-generated.h \
	ck-seat-generated.h \
	ck-session-generated.h \
	act-user-enum-types.h

GTKDOC_CFLAGS= \
	-I$(top_srcdir)/src/libaccountsservice \
	$(GIO_CFLAGS)

GTKDOC_LIBS= \
	$(top_builddir)/src/libaccountsservice/libaccountsservice.la \
	$(GIO_LIBS)

include $(top_srcdir)/gtk-doc.make

CLEANFILES += \
	*-decl*.txt \
	$(NULL)
