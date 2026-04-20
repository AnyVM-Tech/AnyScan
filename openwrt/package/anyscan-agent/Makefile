include $(TOPDIR)/rules.mk

PKG_NAME:=anyscan-agent
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=AnyGPT
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

ANYSCAN_STAGE_ROOT:=$(TOPDIR)/package/$(PKG_NAME)/staging/root
ANYSCAN_FILES_DIR:=$(TOPDIR)/package/$(PKG_NAME)/files

define Package/anyscan-agent-core
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=AnyScan agent core for OpenWrt
  DEPENDS:=+ca-bundle +libgcc
endef

define Package/anyscan-agent-core/description
 Minimal AnyScan agent core package for OpenWrt/GL.iNet devices.
 Installs the agent daemon, procd init script, UCI config, runtime wrapper,
 and bundled detector assets.
endef

define Package/anyscan-agent-core/conffiles
/etc/config/agentd
endef

define Package/anyscan-agent-helpers
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=AnyScan agent bootstrap helpers
  DEPENDS:=+anyscan-agent-core +python3-light
endef

define Package/anyscan-agent-helpers/description
 Bootstrap helper manifest and Python provisioner for the OpenWrt agent.
endef

define Package/anyscan-agent-scanner
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=AnyScan agent scanner support
  DEPENDS:=+anyscan-agent-core
endef

define Package/anyscan-agent-scanner/description
 Scanner adapter manifest/script and the target-built scanner binary.
endef

define Package/anyscan-agent-opal-full
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=AnyScan full Opal worker meta package
  DEPENDS:=+tor +anyscan-agent-helpers +anyscan-agent-scanner
endef

define Package/anyscan-agent-opal-full/description
 Meta package for the full Opal worker profile: core + helpers + scanner + tor.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	test -x "$(ANYSCAN_STAGE_ROOT)/usr/sbin/agentd" || { \
		echo "Missing staged agent binary at $(ANYSCAN_STAGE_ROOT)/usr/sbin/agentd"; \
		echo "Run apps/anyscan/openwrt/prepare-opal-package.sh first."; \
		false; \
	}
endef

define Build/Compile
endef

define Package/anyscan-agent-core/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(ANYSCAN_FILES_DIR)/agentd.config $(1)/etc/config/agentd

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(ANYSCAN_FILES_DIR)/agentd.init $(1)/etc/init.d/agentd

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(ANYSCAN_STAGE_ROOT)/usr/sbin/agentd $(1)/usr/sbin/agentd

	$(INSTALL_DIR) $(1)/usr/libexec/agentd
	$(INSTALL_BIN) $(ANYSCAN_FILES_DIR)/agentd-run.sh $(1)/usr/libexec/agentd/agentd-run.sh

	$(INSTALL_DIR) $(1)/usr/share/agentd/extensions/bundled/manifests
	$(INSTALL_DIR) $(1)/usr/share/agentd/extensions/bundled/rules
	$(INSTALL_DIR) $(1)/usr/share/agentd/extensions/bundled/scripts
	$(CP) $(ANYSCAN_STAGE_ROOT)/usr/share/agentd/extensions/bundled/manifests/. $(1)/usr/share/agentd/extensions/bundled/manifests/
	$(CP) $(ANYSCAN_STAGE_ROOT)/usr/share/agentd/extensions/bundled/rules/. $(1)/usr/share/agentd/extensions/bundled/rules/
	$(CP) $(ANYSCAN_STAGE_ROOT)/usr/share/agentd/extensions/bundled/scripts/. $(1)/usr/share/agentd/extensions/bundled/scripts/

	$(INSTALL_DIR) $(1)/var/lib/agentd/artifacts
endef

define Package/anyscan-agent-helpers/install
	$(INSTALL_DIR) $(1)/usr/share/agentd/extensions
	$(INSTALL_CONF) $(ANYSCAN_STAGE_ROOT)/usr/share/agentd/extensions/bootstrap-provisioner.json $(1)/usr/share/agentd/extensions/bootstrap-provisioner.json
	$(INSTALL_BIN) $(ANYSCAN_STAGE_ROOT)/usr/share/agentd/extensions/bootstrap-provisioner.py $(1)/usr/share/agentd/extensions/bootstrap-provisioner.py
endef

define Package/anyscan-agent-scanner/install
	test -x "$(ANYSCAN_STAGE_ROOT)/usr/libexec/agentd/scanner" || { \
		echo "Missing staged scanner binary at $(ANYSCAN_STAGE_ROOT)/usr/libexec/agentd/scanner"; \
		echo "Run apps/anyscan/openwrt/prepare-opal-package.sh with --scanner-bin first."; \
		false; \
	}
	$(INSTALL_DIR) $(1)/usr/libexec/agentd
	$(INSTALL_BIN) $(ANYSCAN_STAGE_ROOT)/usr/libexec/agentd/scanner $(1)/usr/libexec/agentd/scanner
	$(INSTALL_DIR) $(1)/usr/share/agentd/extensions
	$(INSTALL_CONF) $(ANYSCAN_STAGE_ROOT)/usr/share/agentd/extensions/portscan-adapter.json $(1)/usr/share/agentd/extensions/portscan-adapter.json
	$(INSTALL_BIN) $(ANYSCAN_STAGE_ROOT)/usr/share/agentd/extensions/portscan-adapter.py $(1)/usr/share/agentd/extensions/portscan-adapter.py
endef

define Package/anyscan-agent-opal-full/install
	true
endef

$(eval $(call BuildPackage,anyscan-agent-core))
$(eval $(call BuildPackage,anyscan-agent-helpers))
$(eval $(call BuildPackage,anyscan-agent-scanner))
$(eval $(call BuildPackage,anyscan-agent-opal-full))
