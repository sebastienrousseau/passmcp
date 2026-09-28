# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# The Unix install contract. GNU make reads this file before Makefile, so
# every developer target is pulled in from there and this file adds only
# install, uninstall and the staged smoke test packagers rely on.
#
# PREFIX defaults to /usr/local per the FHS; DESTDIR stages the tree
# elsewhere without changing the paths compiled into it, which is how deb,
# rpm, AUR and Homebrew all build. For a home-directory install:
#   make install PREFIX=$$HOME/.local

include Makefile

PREFIX ?= /usr/local
DESTDIR ?=
BINDIR = $(DESTDIR)$(PREFIX)/bin
MANDIR = $(DESTDIR)$(PREFIX)/share/man/man1
DOCDIR = $(DESTDIR)$(PREFIX)/share/doc/passmcp
BASHCOMPDIR = $(DESTDIR)$(PREFIX)/share/bash-completion/completions
ZSHCOMPDIR = $(DESTDIR)$(PREFIX)/share/zsh/site-functions
FISHCOMPDIR = $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d

.PHONY: install uninstall install-smoke

install: build docs
	install -d $(BINDIR)
	install -m 0755 $(DIST)/$(BINARY_NAME) $(BINDIR)/$(BINARY_NAME)
	install -d $(MANDIR)
	install -m 0644 $(DIST)/man/*.1 $(MANDIR)/
	install -d $(BASHCOMPDIR) $(ZSHCOMPDIR) $(FISHCOMPDIR)
	install -m 0644 $(DIST)/completions/passmcp.bash $(BASHCOMPDIR)/$(BINARY_NAME)
	install -m 0644 $(DIST)/completions/passmcp.zsh  $(ZSHCOMPDIR)/_$(BINARY_NAME)
	install -m 0644 $(DIST)/completions/passmcp.fish $(FISHCOMPDIR)/$(BINARY_NAME).fish
	install -d $(DOCDIR)
	install -m 0644 README.md CHANGELOG.md LICENSE SECURITY.md $(DOCDIR)/

uninstall:
	rm -f $(BINDIR)/$(BINARY_NAME)
	rm -f $(MANDIR)/passmcp.1 $(MANDIR)/passmcp-*.1
	rm -f $(BASHCOMPDIR)/$(BINARY_NAME)
	rm -f $(ZSHCOMPDIR)/_$(BINARY_NAME)
	rm -f $(FISHCOMPDIR)/$(BINARY_NAME).fish
	rm -rf $(DOCDIR)

install-smoke:
	@rm -rf /tmp/passmcp-stage
	@$(MAKE) --no-print-directory install DESTDIR=/tmp/passmcp-stage PREFIX=/usr
	@set -e; \
	for f in usr/bin/$(BINARY_NAME) \
	         usr/share/man/man1/passmcp.1 \
	         usr/share/man/man1/passmcp-check.1 \
	         usr/share/bash-completion/completions/$(BINARY_NAME) \
	         usr/share/zsh/site-functions/_$(BINARY_NAME) \
	         usr/share/fish/vendor_completions.d/$(BINARY_NAME).fish \
	         usr/share/doc/passmcp/README.md; do \
	  test -f "/tmp/passmcp-stage/$$f" || { echo "MISSING: $$f" >&2; exit 1; }; \
	done; \
	test -x /tmp/passmcp-stage/usr/bin/$(BINARY_NAME) || { echo "binary not executable" >&2; exit 1; }
	@echo "install-smoke: staged tree is correct"
	@rm -rf /tmp/passmcp-stage
