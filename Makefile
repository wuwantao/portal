# OpenWrtMakefile for portal program
#
#
# Most ofthe variables used here are defined in
# theinclude directives below. We just need to
# specifya basic description of the package,
# whereto build our program, where to find
# thesource files, and where to install the
#compiled program on the router.
#
# Be verycareful of spacing in this file.
# Indentsshould be tabs, not spaces, and
# thereshould be no trailing whitespace in
# linesthat are not commented.
#
##############################################
 
include $(TOPDIR)/rules.mk
TARGET_CFLAGS += -ggdb3
 
# Nameand release number of this package
PKG_NAME:=portal
PKG_RELEASE:=1
 
 
# Thisspecifies the directory where we're going to build the program.
# Theroot build directory, $(BUILD_DIR), is by default the build_mipsel
#directory in your OpenWrt SDK directory
PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)
 
 
include $(INCLUDE_DIR)/package.mk
 
 
 
# Specifypackage information for this program.
# Thevariables defined here should be self explanatory.
# If youare running Kamikaze, delete the DESCRIPTION
#variable below and uncomment the Kamikaze define
# directivefor the description below
define Package/portal
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+libpcap +libsqlite3 +libnet-1.2.x
	TITLE:=portal --yiqun
endef
 
 
 
# Specifywhat needs to be done to prepare for building the package.
# In ourcase, we need to copy the source files to the build directory.
# This isNOT the default.  The default uses thePKG_SOURCE_URL and the
#PKG_SOURCE which is not defined here to download the source from the web.
# Inorder to just build a simple program that we have just written, it is
# mucheasier to do it this way.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef
 
EXTRA_CFLAGS += $(TARGET_CPPFLAGS)
EXTRA_LDFLAGS += $(TARGET_LDFLAGS)
 
define Build/Compile
	$(call Build/Compile/Default, \
		CCOPTS="$(TARGET_CFLAGS)" \
		INCLUDE="$(EXTRA_CFLAGS)" \
		LDFLAGS="$(EXTRA_LDFLAGS)" \
	)
endef
# We donot need to define Build/Configure or Build/Compile directives
# Thedefaults are appropriate for compiling a simple program such as this one
 
 
# Specifywhere and how to install the program. Since we only have one file,
# theportal executable, install it by copying it to the /bin directory on
# therouter. The $(1) variable represents the root directory on the router running
#OpenWrt. The $(INSTALL_DIR) variable contains a command to prepare the install
#directory if it does not already exist. Likewise $(INSTALL_BIN) contains the
# commandto copy the binary file from its current location (in our case the build
#directory) to the install directory.
define Package/portal/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_DIR) $(1)/data
	$(INSTALL_DIR) $(1)/www
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DIR) $(1)/root
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/rc.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/portal $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/main $(1)/www/cgi-bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sendarp.conf $(1)/etc/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/portal.db $(1)/data/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/select.sh $(1)/root/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/clean.sh $(1)/root/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/startportal $(1)/etc/init.d/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/S99startportal $(1)/etc/rc.d/
endef
 
 
# Thisline executes the necessary commands to compile our program.
# Theabove define directives specify all the information needed, but this
# linecalls BuildPackage which in turn actually uses this information to
# build apackage.
$(eval $(call BuildPackage,portal))
