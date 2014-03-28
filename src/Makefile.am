NULL =
BUILT_SOURCES =
SUBDIRS = . libaccountsservice
INCLUDES = 			\
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\""$(datadir)"\" \
	-DICONDIR=\"$(localstatedir)/lib/AccountsService/icons\" \
	-DUSERDIR=\"$(localstatedir)/lib/AccountsService/users\" \
	-I$(srcdir)		\
	-I$(builddir)		\
	$(POLKIT_CFLAGS)	\
	$(WARN_CFLAGS)

noinst_LTLIBRARIES = libaccounts-generated.la

libaccounts_generated_la_SOURCES = \
	accounts-generated.c		\
	accounts-generated.h		\
	accounts-user-generated.c	\
	accounts-user-generated.h	\
	$(NULL)
BUILT_SOURCES += $(libaccounts_generated_la_SOURCES)

accounts-generated.c accounts-generated.h: $(top_srcdir)/data/org.freedesktop.Accounts.xml Makefile
	gdbus-codegen --generate-c-code accounts-generated --c-namespace Accounts --interface-prefix=org.freedesktop. $(top_srcdir)/data/org.freedesktop.Accounts.xml

accounts-user-generated.c accounts-user-generated.h: $(top_srcdir)/data/org.freedesktop.Accounts.User.xml Makefile
	gdbus-codegen --generate-c-code accounts-user-generated --c-namespace Accounts --interface-prefix=org.freedesktop.Accounts. $(top_srcdir)/data/org.freedesktop.Accounts.User.xml

libexec_PROGRAMS = accounts-daemon

accounts_daemon_SOURCES = 	\
	$(enums_h_sources)	\
	types.h			\
	daemon.h		\
	daemon.c		\
	extensions.c		\
	user-classify.h		\
	user-classify.c		\
	user.h			\
	user.c			\
	util.h			\
	util.c			\
	wtmp-helper.h		\
	wtmp-helper.c		\
	main.c

accounts_daemon_LDADD = 	\
	libaccounts-generated.la	\
	$(POLKIT_LIBS)

EXTRA_DIST = \
	fgetpwent.c	\
	$(NULL)

CLEANFILES = \
	$(BUILT_SOURCES) \
	*.gcda \
	*.gcno \
	$(NULL)

install-data-hook:
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/AccountsService/users"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/AccountsService/icons"
