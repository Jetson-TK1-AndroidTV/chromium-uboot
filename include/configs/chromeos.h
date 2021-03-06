/*
 * Copyright (c) 2015 Google, Inc
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef __configs_chromeos_h__
#define __configs_chromeos_h__

/*
 * In anticipation of implementing early firmware selection, these defines
 * signal the features that are required in U-Boot.
 *
 * The defines munging is thus kept to one Chrome OS-specific file. The
 * upstream boards will define all features as normal for their platform.
 *
 * It is possible that these will be too broad for some platforms - e.g. we
 * may have a platform which wants to use MMC in CONFIG_CROS_RO. However,
 * we can deal with additional needs as we come to them.
 *
 * While it is something of an inconvenience, it may improve boot time on
 * some platforms also.
 *
 *   CONFIG_CROS_LARGE
 *	- Full version as now with factory defined, all features enabled
 *	- This will operate as factory build, or verified boot
 *
 *   CONFIG_CROS_SMALL
 *	- Minimized for use only with verified boot
 *	- No command line, filesystems, LCD console, etc.
 *	- Still has all drivers enabled and can perform verified boot
 *
 *   CONFIG_CROS_RO
 *	- Requires CONFIG_CROS_SMALL. Will only support running RO firmware
 *	- Set up for running VbLoadFirmware() only
 *	- Minimal RAM, no display, no USB, no mass storage (SPI flash only)
 *	- Intended for running in SPL
 *
 *   CONFIG_CROS_RW
 *	- Requires CONFIG_CROS_SMALL. Will only support running RW firmware
 *	- Set up for running VbSelectAndLoadKernel() only
 */

/*
 * This config file defines platform-independent settings that a verified boot
 * firmware must have.
 */

/* Stringify a token */
#ifndef STRINGIFY
#define _STRINGIFY(x)	#x
#define STRINGIFY(x)	_STRINGIFY(x)
#endif

/* Enable verified boot */
#define CONFIG_CHROMEOS

/* Enable test codes */
#ifdef CONFIG_CROS_FULL
#define CONFIG_CHROMEOS_TEST
#endif /* VBOOT_DEBUG */

/* Support constant vboot flag from fdt */
#define CONFIG_CHROMEOS_CONST_FLAG

/* Enable vboot twostop with SPI flash */
#define CONFIG_CHROMEOS_SPI

#define CONFIG_VBOOT_REGION_READ

#ifndef CONFIG_CROS_RO
#define CONFIG_CHROMEOS_DISPLAY

/* Enable legacy vboot_twostop - crosbug.com/p/21810 */
#define CONFIG_CROS_LEGACY_VBOOT
#endif

#ifndef CONFIG_CROS_FULL
#undef CONFIG_CMDLINE
#undef CONFIG_SYS_LONGHELP
#undef CONFIG_SYS_CONSOLE_IS_IN_ENV
#undef CONFIG_SYS_STDIO_DEREGISTER
#undef CONFIG_SYS_HUSH_PARSER
#undef CONFIG_CBMEM_CONSOLE
#undef CONFIG_CMDLINE_EDITING
#undef CONFIG_COMMAND_HISTORY
#undef CONFIG_AUTOCOMPLETE
#undef CONFIG_CONSOLE_MUX
#undef CONFIG_SHOW_BOOT_PROGRESS

#undef CONFIG_I8042_KBD
#define CONFIG_VGA_AS_SINGLE_DEVICE
#undef CONFIG_VIDEO_SW_CURSOR

#undef CONFIG_SUPPORT_VFAT
#undef CONFIG_ATAPI
#undef CONFIG_EFI_PARTITION
#undef CONFIG_DOS_PARTITION
#undef CONFIG_MAC_PARTITION
#undef CONFIG_ISO_PARTITION
#undef CONFIG_PARTITION_UUIDS

#undef CONFIG_CMD_PART
#undef CONFIG_CMD_CBFS
#undef CONFIG_CMD_EXT4
#undef CONFIG_CMD_EXT4_WRITE
#undef CONFIG_CMD_NET
#undef CONFIG_CMD_CRC32
#undef CONFIG_CMD_CROS_EC

#undef CONFIG_USB_HOST_ETHER
#undef CONFIG_USB_ETHER_ASIX
#undef CONFIG_USB_ETHER_SMSC95XX

#undef CONFIG_GENERIC_MMC
#undef CONFIG_MMC

#define DYNAMIC_CRC_TABLE
#undef CONFIG_BOOTDELAY

#endif

/* Enable graphics display */
#ifdef CONFIG_CHROMEOS_DISPLAY
#define CONFIG_LCD_BMP_RLE8
#define CONFIG_LZMA
#define CONFIG_VIDEO_NO_TEXT
#else
#undef CONFIG_LCD
#undef CONFIG_EXYNOS_FB
#undef CONFIG_EXYNOS_DP
#undef CONFIG_VIDEO_ANALOGIX
#undef CONFIG_VIDEO_PARADE
#undef CONFIG_CMD_BMP
#endif

#ifdef CONFIG_CROS_RO
#undef CONFIG_USB_EHCI
#undef CONFIG_USB_EHCI_PCI
#undef CONFIG_SYS_USB_EHCI_MAX_ROOT_PORTS
#undef CONFIG_USB_MAX_CONTROLLER_COUNT
#undef CONFIG_USB_STORAGE
#undef CONFIG_USB_KEYBOARD
#undef CONFIG_SYS_USB_EVENT_POLL

#undef CONFIG_CMD_USB
#undef CONFIG_CMD_SOUND
#undef CONFIG_SOUND_INTEL_HDA
#undef CONFIG_CRC32_VERIFY
#undef CONFIG_TPM
#undef CONFIG_FIT
#define CONFIG_CRC32
#undef CONFIG_LZO

/* Limited memory so use a smaller recorded console */
#undef CONFIG_RECORDED_CONSOLE_SIZE
#define CONFIG_RECORDED_CONSOLE_SIZE 3000

#else
/* USB is used in recovery mode */
#define CONFIG_CHROMEOS_USB
#endif

/*
 * Enable this feature to embed crossystem data into device tree before booting
 * the kernel. We add quite a few things to the FDT, including a 16KB binary
 * blob.
 * #define CONFIG_OF_BOARD_SETUP
 */
#define CONFIG_SYS_FDT_PAD	0x8000

/* Make sure that the safe version of printf() is compiled in. */
#define CONFIG_SYS_VSNPRINTF

/*
 * This is the default kernel command line to a Chrome OS kernel. An ending
 * space character helps us concatenate more arguments.
 */
#ifndef CONFIG_BOOTARGS
#define CONFIG_BOOTARGS
#endif
#define CHROMEOS_BOOTARGS "cros_secure " CONFIG_BOOTARGS " "

#ifndef CONFIG_DIRECT_BOOTARGS
#define CONFIG_DIRECT_BOOTARGS
#endif
#ifndef CONFIG_EXTRA_BOOTARGS
#define CONFIG_EXTRA_BOOTARGS
#endif

/*******************************************************************************
 * Non-verified boot script                                                    *
 ******************************************************************************/

/*
 * Defines the regen_all variable, which is used by other commands
 * defined in this file.  Usage is to override one or more of the environment
 * variables and then run regen_all to regenerate the environment.
 *
 * Args from other scipts in this file:
 *   bootdev_bootargs: Filled in by other commands below based on the boot
 *       device.
 *
 * Args:
 *   common_bootargs: A copy of the default bootargs so we can run regen_all
 *       more than once.
 *   dev_extras: Placeholder space for developers to put their own boot args.
 *   extra_bootargs: Filled in by update_firmware_vars.py script in some cases.
 */
#define CONFIG_REGEN_ALL_SETTINGS \
	"common_bootargs=cros_legacy " CONFIG_DIRECT_BOOTARGS "\0" \
	\
	"dev_extras=\0" \
	"extra_bootargs=" \
		CONFIG_EXTRA_BOOTARGS "\0" \
	"bootdev_bootargs=\0" \
	\
	"regen_all=" \
		"setenv bootargs " \
			"${common_bootargs} " \
			"${dev_extras} " \
			"${extra_bootargs} " \
			"${bootdev_bootargs}\0"

/*
 * Defines ext2_boot and run_disk_boot_script.
 *
 * The run_disk_boot_script runs a u-boot script on the boot disk.  At the
 * moment this is used to allow the boot disk to choose a partion to boot from,
 * but could theoretically be used for more complicated things.
 *
 * The ext2_boot script boots from an ext2 device.
 *
 * Args from other scipts in this file:
 *   devtype: The device type we're booting from, like "usb" or "mmc"
 *   devnum: The device number (depends on devtype).  If we're booting from
 *       extranal MMC (for instance), this would be 1
 *   devname: The linux device name that will be assigned, like "sda" or
 *       mmcblk0p
 *
 * Args expected to be set by the u-boot script in /u-boot/boot.scr.uimg:
 *   rootpart: The root filesystem partion; we default to 3 in case there are
 *       problems reading the boot script.
 *   cros_bootfile: The name of the kernel in the root partition; we default to
 *       "/boot/vmlinux.uimg"
 *
 * Other args:
 *   script_part: The FAT partion we'll look for a boot script in.
 *   script_img: The name of the u-boot script.
 *
 * When we boot from an ext2 device, we will look at partion 12 (0x0c) to find
 * a u-boot script (as /u-boot/boot.scr.uimg).  That script is expected to
 * override "rootpart" and "cros_bootfile" as needed to select which partition
 * to boot from.
 *
 * USB download support:
 *
 * Once we have loaded the kernel from the selected device successfully,
 * we check whether a kernel has in fact been provided through the USB
 * download feature. In that case the kernaddr environment variable will
 * be set. It might seem strange that we load the original kernel and
 * then ignore it, but we try to load the kernel from a number of different
 * places. If the USB disk fails (because there is no disk inserted or
 * it is invalid) we don't want to pull in the kernaddr kernel and boot it
 * with USB as the root disk. So allow the normal boot failover to occur,
 * and only insert the kernaddr kernel when we actually have decided
 * what to boot from.
 */
#define CONFIG_EXT2_BOOT_HELPER_SETTINGS \
	"rootpart=5\0" \
	"cros_bootfile=/boot/vmlinux.uimg\0" \
	\
	"script_part=c\0" \
	"script_img=/u-boot/boot.scr.uimg\0" \
	\
	"run_disk_boot_script=" \
		"if fatload ${devtype} ${devnum}:${script_part} " \
				"${loadaddr} ${script_img}; then " \
			"source ${loadaddr}; " \
			"echo done; " \
		"fi\0" \
	\
	"regen_ext2_bootargs=" \
		"setenv bootdev_bootargs root=${devname} rootwait ro; " \
		"run regen_all\0" \
	\
	"ext2_boot=" \
		"run regen_ext2_bootargs; " \
		"setenv rootpart 5; "\
		"if ext2load ${devtype} ${devnum}:${rootpart} " \
			"${loadaddr} ${cros_bootfile}; then " \
			"if test \"${kernaddr}\" != \"\"; then "\
				"echo \"Using bundled kernel\"; "\
				"bootm ${kernaddr};" \
			"fi; "\
			"bootm ${loadaddr};" \
		"fi\0"

/*
 * Network-boot related settings.
 *
 * At the moment, we support:
 *   - initramfs factory install (tftp kernel with factory installer initramfs)
 *   - full network root booting (tftp kernel and initial ramdisk)
 *   - nfs booting (tftp kernel and point root to NFS)
 *
 * Network booting is enabled if you have an ethernet adapter plugged in at boot
 * and also have set tftpserverip/nfsserverip to something other than 0.0.0.0.
 * For full network booting or initramfs factory install you just need
 * tftpserverip. To choose full network booting over initramfs factory intsall,
 * you have to set has_initrd=1. For full NFS root you neet to set both
 * tftpserverip and nfsserverip.
 */
#define CONFIG_NETBOOT_SETTINGS \
	"tftpserverip=0.0.0.0\0" \
	"nfsserverip=0.0.0.0\0" \
	"has_initrd=0\0" \
	\
	"rootaddr=" STRINGIFY(CONFIG_INITRD_ADDRESS) "\0" \
	"initrd_high=0xffffffff\0" \
	\
	"regen_nfsroot_bootargs=" \
		"setenv bootdev_bootargs " \
			"dev=/dev/nfs4 rw nfsroot=${nfsserverip}:${rootpath} " \
			"ip=dhcp noinitrd; " \
		"run regen_all\0" \
	"regen_initrdroot_bootargs=" \
		"setenv bootdev_bootargs " \
			"rw root=/dev/ram0 ramdisk_size=512000 cros_netboot; " \
		"run regen_all\0" \
	"regen_initramfs_install_bootargs=" \
		"setenv bootdev_bootargs " \
			"lsm.module_locking=0 cros_netboot_ramfs " \
			"cros_factory_install cros_secure; " \
		"run regen_all\0" \
	\
	"tftp_setup=" \
		"setenv tftpkernelpath " \
			"/tftpboot/vmlinux.uimg; " \
		"setenv tftprootpath " \
			"/tftpboot/initrd.uimg; " \
		"setenv rootpath " \
			"/export/nfsroot; " \
		"setenv autoload n\0" \
	"initrdroot_boot=" \
		"run tftp_setup; " \
		"run regen_initrdroot_bootargs; " \
		"bootp; " \
		"if tftpboot ${rootaddr} ${tftpserverip}:${tftprootpath} && " \
		"   tftpboot ${loadaddr} ${tftpserverip}:${tftpkernelpath}; " \
		"then " \
			"bootm ${loadaddr} ${rootaddr}; " \
		"else " \
			"echo 'ERROR: Could not load root/kernel from TFTP'; " \
			"exit; " \
		"fi\0" \
	"initramfs_boot=" \
		"run tftp_setup; "\
		"run regen_initramfs_install_bootargs; "\
		"bootp; " \
		"if tftpboot ${loadaddr} ${tftpserverip}:${tftpkernelpath}; " \
		"then " \
			"bootm ${loadaddr}; "\
		"else " \
			"echo 'ERROR: Could not load kernel from TFTP'; " \
			"exit; " \
		"fi\0" \
	"tftp_ext2_boot=" \
		"run tftp_setup; " \
		"run regen_ext2_bootargs; " \
		"bootp; " \
		"if tftpboot ${loadaddr} ${tftpserverip}:${tftpkernelpath}; " \
		"then " \
			"bootm ${loadaddr}; " \
		"else " \
			"echo 'ERROR: Could not load kernel from TFTP'; " \
			"exit; " \
		"fi\0" \
	"nfsroot_boot=" \
		"run tftp_setup; " \
		"run regen_nfsroot_bootargs; " \
		"bootp; " \
		"if tftpboot ${loadaddr} ${tftpserverip}:${tftpkernelpath}; " \
		"then " \
			"bootm ${loadaddr}; " \
		"else " \
			"echo 'ERROR: Could not load kernel from TFTP'; " \
			"exit; " \
		"fi\0" \
	\
	"net_boot=" \
		"if test ${ethact} != \"\"; then " \
			"if test ${tftpserverip} != \"0.0.0.0\"; then " \
				"if test ${nfsserverip} != \"0.0.0.0\"; then " \
					"run nfsroot_boot; " \
				"fi; " \
				"if test ${has_initrd} != \"0\"; then " \
					"run initrdroot_boot; " \
				"else " \
					"run initramfs_boot; " \
				"fi; " \
			"fi; " \
		"fi\0" \

/*
 * Our full set of extra enviornment variables.
 *
 * A few notes:
 * - Right now, we can only boot from one USB device.  Need to fix this once
 *   usb works better.
 * - We define "non_verified_boot", which is the normal boot command unless
 *   it is overridden in the FDT.
 * - When we're running securely, the FDT will specify to call vboot_twostop
 *   directly.
 */
#undef CONFIG_CHROMEOS_EXTRA_ENV_SETTINGS

#ifdef CONFIG_CROS_RO
#define CONFIG_CHROMEOS_EXTRA_ENV_SETTINGS
#else
#define CONFIG_CHROMEOS_EXTRA_ENV_SETTINGS \
	CONFIG_REGEN_ALL_SETTINGS \
	CONFIG_EXT2_BOOT_HELPER_SETTINGS \
	CONFIG_NETBOOT_SETTINGS \
	\
	"set_devname=" \
		"part uuid ${devtype} ${devnum}:${rootpart} rootuuid; " \
		"setenv devname PARTUUID=${rootuuid}\0" \
	\
	"usb_boot=setenv devtype usb; " \
		"setenv devnum 0; " \
		"run run_disk_boot_script;" \
		"run set_devname; " \
		"run ext2_boot\0" \
	\
	"mmc_setup=" \
		"mmc dev ${devnum}; " \
		"mmc rescan; " \
		"setenv devtype mmc\0" \
	"mmc_boot=" \
		"run mmc_setup; " \
		"run run_disk_boot_script;" \
		"run set_devname; " \
		"run ext2_boot\0" \
	"mmc0_boot=setenv devnum 0; " \
		"run mmc_boot\0" \
	"mmc1_boot=setenv devnum 1; " \
		"run mmc_boot\0" \
	"mmc0_tftpboot=setenv devnum 0; " \
		"run mmc_setup; " \
		"run tftp_ext2_boot\0" \
	\
	"nvboot=" \
		"usb start; " \
		"run net_boot; " \
		"run usb_boot; " \
		\
		"run mmc1_boot; " \
		"run mmc0_boot\0"
#endif

#define CONFIG_NON_VERIFIED_BOOTCOMMAND "run nvboot"

#endif /* __configs_chromeos_h__ */
