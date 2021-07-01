CC     = cc
CFLAGS = -Wall -O2 -Wextra
prefix = /usr/local
PREFIX = $(prefix)

arply:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) arply.c -o arply

install: arply
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mv -f arply $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/arply

clean:
	rm -f arply

.PHONY: arply install uninstall clean
