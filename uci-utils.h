#ifndef UCI_UTILS_H
#define UCI_UTILS_H

#include "commotion-service-manager.h"

#define UCIPATH "/opt/luci-commotion/etc/config"

int uci_remove(ServiceInfo *i);
int uci_write(ServiceInfo *i);

#endif