SRC=src
TARGET=bin/ipxe.usb
EMBEDDED_SCRIPT=ovf/script.ipxe

rom:
	$(MAKE) -C $(SRC) $(TARGET) EMBED=$(shell readlink -f $(EMBEDDED_SCRIPT))

ovf/ipxe-flat.vmdk: rom
	truncate -s 2097152 $@
	dd if=$(SRC)/$(TARGET) of=$@ conv=notrunc

ovf: ovf/ipxe-flat.vmdk
