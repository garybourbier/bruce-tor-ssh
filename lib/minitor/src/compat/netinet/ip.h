/*
 * netinet/ip.h — compat stub for ESP32/lwIP.
 *
 * ESP-IDF/lwIP provides netinet/in.h (already included before this in port.h)
 * but not netinet/ip.h. Minitor's port.h includes it defensively; nothing in
 * Minitor's actual code uses the 'struct ip' IP header layout it defines.
 */
#ifndef _NETINET_IP_H
#define _NETINET_IP_H

#include <netinet/in.h>
#include <lwip/ip.h>

#endif /* _NETINET_IP_H */
