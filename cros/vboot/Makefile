obj-$(CONFIG_CHROMEOS) += boot_device.o
obj-$(CONFIG_SANDBOX) += boot_device_host.o
obj-$(CONFIG_CHROMEOS_IDE) += boot_device_ide.o
obj-$(CONFIG_MMC) += boot_device_mmc.o
obj-$(CONFIG_CHROMEOS_USB) += boot_device_usb.o
obj-$(CONFIG_SCSI_AHCI) += boot_device_scsi.o
obj-$(CONFIG_CHROMEOS) += display.o
obj-$(CONFIG_CHROMEOS) += ec.o
obj-$(CONFIG_CHROMEOS) += keyboard.o
obj-$(CONFIG_CROS_LEGACY_VBOOT) += load_firmware.o
obj-$(CONFIG_CHROMEOS) += misc.o
obj-$(CONFIG_CHROMEOS) += nvstorage.o
ifndef CONFIG_CROS_RO
obj-$(CONFIG_CHROMEOS) += nvstorage_disk.o
endif
ifdef CONFIG_CROS_EC
obj-$(CONFIG_CHROMEOS) += nvstorage_cros_ec.o
endif
obj-$(CONFIG_CHROMEOS) += stages.o
obj-$(CONFIG_CHROMEOS) += switches.o
obj-$(CONFIG_CHROMEOS) += tlcl_stub.o
obj-$(CONFIG_CHROMEOS) += utility.o
