# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for Bit-Twist project
# Copyright (C) 2006 - 2023 Addy Yeow <ayeowch@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

SHELL = /bin/sh

prefix = /usr/local
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
mandir = ${prefix}/share/man/man1

# Bit-Twist 3.1 and earlier was using /usr instead of /usr/local.
# These old paths are defined below to allow `sudo make uninstall` to also
# remove any installation of Bit-Twist 3.1 or earlier.
old_prefix = /usr
old_exec_prefix = ${old_prefix}
old_bindir = ${old_exec_prefix}/bin
old_mandir = ${old_prefix}/share/man/man1

CC ?= gcc
DEBUG = -g
CFLAGS ?= -std=gnu17
CFLAGS += -O2
CFLAGS += ${DEBUG} -Wall
SRC = src
DOC = doc

CPPCHECK ?= cppcheck

CLANG_FORMAT ?= clang-format

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

all: bittwist bittwiste

bittwist:
	$(CC) $(CFLAGS) $(SRC)/bittwist.c $(SRC)/token_bucket.c -o $(SRC)/bittwist -I/usr/local/include -L/usr/local/lib -lpcap

bittwiste:
	$(CC) $(CFLAGS) $(SRC)/bittwiste.c $(SRC)/tinymt/tinymt64.c $(SRC)/template_pcap.c -o $(SRC)/bittwiste -I $(SRC)/tinymt -I/usr/local/include -L/usr/local/lib -lpcap

clean:
	rm -f $(SRC)/bittwist $(SRC)/bittwiste

check:
	$(CPPCHECK) --enable=warning $(SRC)

format:
	$(CLANG_FORMAT) -i src/def.h src/token_bucket.h src/token_bucket.c src/template_pcap.h src/template_pcap.c src/bittwist.h src/bittwist.c src/bittwiste.h src/bittwiste.c

install:
	mkdir -p $(bindir)
	chmod 755 $(bindir)
	$(INSTALL_PROGRAM) $(SRC)/bittwist $(SRC)/bittwiste $(bindir)
	mkdir -p $(mandir)
	chmod 755 $(mandir)
	$(INSTALL_DATA) $(DOC)/bittwist.1 $(DOC)/bittwiste.1 $(mandir)

uninstall:
	@rm -vf $(wildcard $(bindir)/bittwist)
	@rm -vf $(wildcard $(bindir)/bittwiste)
	@rm -vf $(wildcard $(mandir)/bittwist.1)
	@rm -vf $(wildcard $(mandir)/bittwiste.1)
	@rm -vf $(wildcard $(old_bindir)/bittwist)
	@rm -vf $(wildcard $(old_bindir)/bittwiste)
	@rm -vf $(wildcard $(old_mandir)/bittwist.1)
	@rm -vf $(wildcard $(old_mandir)/bittwiste.1)
