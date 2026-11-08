BUILDDIR ?= build

all: $(BUILDDIR)/build.ninja
	meson compile -C $(BUILDDIR)

$(BUILDDIR)/build.ninja:
	meson setup $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR)

.PHONY: all clean
