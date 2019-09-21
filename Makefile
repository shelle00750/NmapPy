all:

clean:

install:
	chmod 755 setup.py
	chmod 755 run.sh
	chmod 755 nmappy.py
	mkdir -p $(DESTDIR)/opt/nmappy/
	mkdir -p $(DESTDIR)/usr/share/doc/nmappy/
	mkdir -p $(DESTDIR)/opt/nmappy/tools/
	mkdir -p $(DESTDIR)/usr/bin/
	cp setup.py $(DESTDIR)/opt/nmappy/
	cp LICENSE $(DESTDIR)/opt/nmappy/
	cp Makefile $(DESTDIR)/opt/nmappy/
	cp README.md $(DESTDIR)/opt/nmappy/
	cp README.md $(DESTDIR)/usr/share/doc/nmappy/
	cp run.sh $(DESTDIR)/opt/nmappy/
	cp run.sh $(DESTDIR)/usr/bin/
	cp nmappy.py $(DESTDIR)/opt/nmappy/
	cp -r tools $(DESTDIR)/opt/nmappy/
