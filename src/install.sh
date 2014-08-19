#! /bin/sh


mkdir /usr/local/dshb
cp dshb.py /usr/local/dshb/
cp dshb.conf /usr/local/dshb/
ln -s /usr/local/dshb/dshb.py /etc/init.d/dshb
update-rc.d dshb defaults 99
cd ~
