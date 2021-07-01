CC     = cc
CFLAGS = -Wall -O2 -Wextra
prefix = /usr/local

arply:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) arply.c -o arply

install: arply
	mkdir -p $(DESTDIR)$(prefix)/bin
	mv -f arply $(DESTDIR)$(prefix)/bin

uninstall:
	rm -f $(DESTDIR)$(prefix)/bin/arply

clean:
	rm -f arply

.PHONY: arply install uninstall clean
