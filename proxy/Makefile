#
# Sentinel DDoS Core - Proxy Component Makefile
#
# Builds both the kernel module and userspace loader
#

# Kernel module parameters
KERNEL_MODULE := sentinel_proxy
KERNEL_SOURCES := sentinel_proxy.c
KERNEL_OBJ := $(KERNEL_SOURCES:.c=.o)

# Userspace loader parameters
USERSPACE_LOADER := sentinel_proxy_loader
USERSPACE_SOURCES := sentinel_loader.c
USERSPACE_OBJ := $(USERSPACE_SOURCES:.c=.o)

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -O2 -I.
CFLAGS += -D_POSIX_C_SOURCE=200809L
CFLAGS += -fPIC

# Kernel module build flags
# NOTE: Must use $(CURDIR) not $(PWD). When invoked via 'make -C proxy' from
# the root Makefile, $(PWD) still holds the parent's working directory, causing
# kbuild to search the wrong path for obj-m. $(CURDIR) is always correct.
KERNEL_BUILD := make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules
KERNEL_CLEAN := make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean

# Default target
all: kernel_module userspace_loader

# ============================================================================
# KERNEL MODULE BUILD
# ============================================================================

kernel_module: $(KERNEL_SOURCES)
	@echo "Building kernel module..."
	$(KERNEL_BUILD)
	@if [ -f $(KERNEL_MODULE).ko ]; then \
		echo "Kernel module built: $(KERNEL_MODULE).ko"; \
	fi

# ============================================================================
# USERSPACE LOADER BUILD
# ============================================================================

userspace_loader: $(USERSPACE_SOURCES)
	@echo "Building userspace loader..."
	$(CC) $(CFLAGS) -o $(USERSPACE_LOADER) $(USERSPACE_SOURCES) -Wl,--no-as-needed
	@echo "Userspace loader built: $(USERSPACE_LOADER)"

# ============================================================================
# INSTALLATION
# ============================================================================

install: install_kernel_module install_userspace_loader

install_kernel_module: kernel_module
	@echo "Installing kernel module..."
	@if [ ! -f $(KERNEL_MODULE).ko ]; then \
		echo "Error: $(KERNEL_MODULE).ko not found. Build the module first."; \
		exit 1; \
	fi
	@if [ ! -d /lib/modules/$(shell uname -r)/kernel/drivers/sentinel ]; then \
		mkdir -p /lib/modules/$(shell uname -r)/kernel/drivers/sentinel; \
	fi
	cp $(KERNEL_MODULE).ko /lib/modules/$(shell uname -r)/kernel/drivers/sentinel/
	depmod -a
	@echo "Kernel module installed"

install_userspace_loader: userspace_loader
	@echo "Installing userspace loader..."
	@if [ ! -f $(USERSPACE_LOADER) ]; then \
		echo "Error: $(USERSPACE_LOADER) not found. Build it first."; \
		exit 1; \
	fi
	cp $(USERSPACE_LOADER) /usr/local/bin/
	chmod +x /usr/local/bin/$(USERSPACE_LOADER)
	@echo "Userspace loader installed to /usr/local/bin"

# ============================================================================
# UNINSTALLATION
# ============================================================================

uninstall: uninstall_kernel_module uninstall_userspace_loader

uninstall_kernel_module:
	@echo "Uninstalling kernel module..."
	@if [ -f /lib/modules/$(shell uname -r)/kernel/drivers/sentinel/$(KERNEL_MODULE).ko ]; then \
		rm /lib/modules/$(shell uname -r)/kernel/drivers/sentinel/$(KERNEL_MODULE).ko; \
		depmod -a; \
		echo "Kernel module uninstalled"; \
	fi

uninstall_userspace_loader:
	@echo "Uninstalling userspace loader..."
	@if [ -f /usr/local/bin/$(USERSPACE_LOADER) ]; then \
		rm /usr/local/bin/$(USERSPACE_LOADER); \
		echo "Userspace loader uninstalled"; \
	fi

# ============================================================================
# LOAD/UNLOAD TARGETS (for development)
# ============================================================================

load: kernel_module
	@echo "Loading kernel module..."
	insmod ./$(KERNEL_MODULE).ko
	@echo "Module loaded. Check with: lsmod | grep $(KERNEL_MODULE)"

unload:
	@echo "Unloading kernel module..."
	@if lsmod | grep -q $(KERNEL_MODULE); then \
		rmmod $(KERNEL_MODULE); \
		echo "Module unloaded"; \
	else \
		echo "Module not loaded"; \
	fi

reload: unload load

# ============================================================================
# DEBUGGING TARGETS
# ============================================================================

dmesg:
	@echo "=== Kernel messages (last 20 lines) ==="
	@dmesg | tail -20

dmesg-follow:
	dmesg -w

info:
	@echo "Kernel module: $(KERNEL_MODULE)"
	@echo "Kernel sources: $(KERNEL_SOURCES)"
	@echo "Userspace loader: $(USERSPACE_LOADER)"
	@echo "Userspace sources: $(USERSPACE_SOURCES)"
	@echo ""
	@echo "Kernel version: $(shell uname -r)"
	@echo "Kernel build: /lib/modules/$(shell uname -r)/build"
	@echo ""
	@echo "Targets:"
	@echo "  make                 - Build kernel module and userspace loader"
	@echo "  make kernel_module   - Build only kernel module"
	@echo "  make userspace_loader - Build only userspace loader"
	@echo "  make install         - Install both components"
	@echo "  make uninstall       - Uninstall both components"
	@echo "  make load            - Load kernel module (dev)"
	@echo "  make unload          - Unload kernel module (dev)"
	@echo "  make reload          - Reload kernel module (dev)"
	@echo "  make dmesg           - Show kernel messages"
	@echo "  make dmesg-follow    - Follow kernel messages (real-time)"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make help            - Show this help"

help: info

# ============================================================================
# KBUILD MODULE CONFIGURATION
# ============================================================================

obj-m := sentinel_proxy.o

# ============================================================================
# CLEANUP
# ============================================================================

clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(USERSPACE_OBJ) $(USERSPACE_LOADER)
	@rm -f modules.order Module.symvers
	@rm -rf .tmp_versions
	@rm -f *.o *.ko *.mod.c *.mod.o .*.cmd .*.o.d
	$(KERNEL_CLEAN)
	@echo "Clean complete"

distclean: clean unload uninstall
	@echo "Distribution clean complete"

.PHONY: all kernel_module userspace_loader install install_kernel_module \
        install_userspace_loader uninstall uninstall_kernel_module \
        uninstall_userspace_loader load unload reload dmesg dmesg-follow \
        info help clean distclean
