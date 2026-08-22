#if !defined(LITE_VERSION)

#include "tor_ssh.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/settings.h"
#include "core/utils.h"
#include "core/wifi/wifi_common.h"

#include <SD.h>
#include <WiFi.h>
#include <esp_task_wdt.h>
#include <esp_system.h>
#include <sys/stat.h>
#include <mbedtls/ctr_drbg.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_heap_caps.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <cstdio>
#include <cstring>
#include <vector>

#include "core/sd_functions.h"

// LibSSH-ESP32 internal DRBG — reseed with hardware RNG before use
// to avoid blocking on slow entropy sources when wolfSSL is also linked
extern "C" {
    extern mbedtls_ctr_drbg_context ssh_mbedtls_ctr_drbg;
}
static int _esp32_entropy(void *, unsigned char *out, size_t len) {
    esp_fill_random(out, len);
    return 0;
}
static void _reseed_ssh_drbg() {
    uint8_t seed[32];
    esp_fill_random(seed, sizeof(seed));
    mbedtls_ctr_drbg_free(&ssh_mbedtls_ctr_drbg);
    mbedtls_ctr_drbg_init(&ssh_mbedtls_ctr_drbg);
    mbedtls_ctr_drbg_seed(&ssh_mbedtls_ctr_drbg, _esp32_entropy, nullptr, seed, sizeof(seed));
}

extern "C" {
#include "minitor.h"
extern volatile int g_minitor_relay_count;
// Repoint where incoming .onion streams are forwarded (default loopback). Used
// by gateway mode to relay to a LAN backend instead of the on-device server.
void v_set_local_connection_addr(const char *addr);
// Register a progress callback invoked (on Minitor's relay task) during the
// consensus fetch, so we can animate the on-screen progress safely.
void v_set_minitor_progress_cb(void (*cb)(int));
}

// Set to true while worker is blocked in d_minitor_INIT() consensus download.
// The main task reads this to know when to refresh the relay-count display.
static volatile bool g_tor_in_consensus = false;

// ── Configuration ──────────────────────────────────────────────────────────────

// SSH port exposed on the .onion address
#define TOR_SSH_ONION_PORT  22
// Local port the SSH server binds to on loopback — Minitor proxies this
#define TOR_SSH_LOCAL_PORT  2222
// Hidden service keys directory — Minitor creates this on first run and
// generates keys inside it.  Must NOT be pre-created; if the dir exists
// Minitor assumes keys are already present and skips key generation.
#define TOR_ONION_DIR       "/sd/tor_ssh/hs"
// SSH host key file (persisted on SD — generated once, reused every boot)
#define TOR_SSH_HOST_KEY    "/sd/tor_ssh/ssh_host_ecdsa_key"
// Optional gateway config: if this file exists and holds "IP:PORT", the .onion
// forwards straight to that LAN backend (e.g. a PC's sshd) instead of running the
// on-device shell — the board becomes a Tor gateway. Absent → local shell.
#define TOR_SSH_FORWARD_CFG "/sd/tor_ssh/forward.txt"

// Gateway (forward) mode state, loaded from TOR_SSH_FORWARD_CFG at start.
static bool g_forward_mode  = false;
static char g_forward_ip[16] = {0};
static int  g_forward_port  = 22;

// Parse TOR_SSH_FORWARD_CFG ("IP:PORT"). Sets g_forward_mode on success.
static void _load_forward_config() {
    g_forward_mode = false;
    int fd = open(TOR_SSH_FORWARD_CFG, O_RDONLY);
    if (fd < 0) return;
    char b[64] = {0};
    int n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return;
    char ip[16] = {0};
    int port = 0;
    if (sscanf(b, "%15[0-9.]:%d", ip, &port) == 2 && port > 0 && port < 65536) {
        strncpy(g_forward_ip, ip, sizeof(g_forward_ip) - 1);
        g_forward_port = port;
        g_forward_mode = true;
    }
}

// ── Internal state ─────────────────────────────────────────────────────────────

static char     g_onion_addr[70]  = {0};
static ssh_bind g_sshbind          = nullptr;

// ── SD log (survives reboot — lets us diagnose crashes without serial) ─────────

#define TOR_LOG_FILE "/sd/tor_ssh/debug.log"

// POSIX write — avoids Arduino SD library which uses a different SPI lock
// than the ESP-IDF sdspi_host used by Minitor's POSIX VFS (same hardware,
// different semaphores → concurrent access corrupts the SPI bus).
static void _sdlog(const char *msg) {
    Serial.println(msg);
    int fd = open(TOR_LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    write(fd, msg, strlen(msg));
    write(fd, "\n", 1);
    fsync(fd);
    close(fd);
}

// ── Display helpers ────────────────────────────────────────────────────────────
// Layout (320x170 landscape).  The screen is intentionally FROZEN during the Tor
// consensus download: the ST7789 and the SD card sit on one shared SPI bus
// (TFT_CS=41, SDCARD_CS=13) and Minitor drives the SD through the ESP-IDF sdspi
// VFS — outside the Arduino SPI lock — so any TFT write while consensus is
// running corrupts the bus.  We therefore draw only at safe points and reserve
// fixed regions so status text can never bleed into the progress bar.
#define UI_PHASE_Y     24                        // current-step line under the header
#define UI_DETAIL_Y0   40                        // top of the scrolling detail region
#define UI_BAR_H       14
#define UI_LINE_H      10                         // FP font (6x8) + 2px leading
#define UI_BAR_Y       (tftHeight - UI_BAR_H - 6)
#define UI_DETAIL_BOT  (UI_BAR_Y - 4)             // detail region must stop above the bar

static int _detail_y = UI_DETAIL_Y0;

static void _header(const char *title) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.drawCentreString(title, tftWidth / 2, 3, 1);
    tft.drawLine(0, 20, tftWidth, 20, bruceConfig.priColor);
    tft.setTextSize(FP);
    _detail_y = UI_DETAIL_Y0;
}

// Print one detail line inside the bounded region.  When the region is full we
// wrap back to its top (clearing it) instead of ever overwriting the bar.
static void _status(const char *msg, uint16_t color = TFT_WHITE) {
    if (_detail_y + UI_LINE_H > UI_DETAIL_BOT) {
        tft.fillRect(0, UI_DETAIL_Y0, tftWidth, UI_DETAIL_BOT - UI_DETAIL_Y0, bruceConfig.bgColor);
        _detail_y = UI_DETAIL_Y0;
    }
    tft.setTextSize(FP);
    tft.setTextColor(color, bruceConfig.bgColor);
    tft.setCursor(4, _detail_y);
    tft.print(msg);
    _detail_y += UI_LINE_H;
}

// Draw the current phase name (own cleared line) plus the progress bar with the
// percentage centred inside it.  Resets the detail region so each phase starts
// with a clean slate below its title — no leftover text near the bar.
static void _progress(uint8_t pct, const char *label) {
    // phase line
    tft.fillRect(0, UI_PHASE_Y, tftWidth, UI_LINE_H, bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setCursor(4, UI_PHASE_Y);
    tft.print(label);

    // fresh detail region for this phase
    tft.fillRect(0, UI_DETAIL_Y0, tftWidth, UI_DETAIL_BOT - UI_DETAIL_Y0, bruceConfig.bgColor);
    _detail_y = UI_DETAIL_Y0;

    // progress bar
    int bar_w  = tftWidth - 16;
    int fill_w = (bar_w - 2) * pct / 100;
    tft.drawRect(8, UI_BAR_Y, bar_w, UI_BAR_H, bruceConfig.priColor);
    tft.fillRect(9, UI_BAR_Y + 1, bar_w - 2, UI_BAR_H - 2, bruceConfig.bgColor);
    if (fill_w > 0)
        tft.fillRect(9, UI_BAR_Y + 1, fill_w, UI_BAR_H - 2, bruceConfig.priColor);

    // percentage centred inside the bar; transparent bg so it sits over the fill
    char pctbuf[8];
    snprintf(pctbuf, sizeof(pctbuf), "%u%%", (unsigned)pct);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE);
    tft.drawCentreString(pctbuf, tftWidth / 2, UI_BAR_Y + 3, 1);
}

static void _show_onion(const char *addr) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.drawCentreString("Tor SSH  Ready", tftWidth / 2, 4, 1);
    tft.drawLine(0, 24, tftWidth, 24, bruceConfig.priColor);

    tft.setTextSize(FP);
    tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
    tft.drawString("ssh bruce@<onion>  -p 22", 8, 34);

    // .onion in a bordered box, split across two lines to fit the 320px width
    String a = String(addr);
    int box_y = 50;
    tft.drawRect(4, box_y, tftWidth - 8, 32, bruceConfig.priColor);
    tft.setTextColor(TFT_CYAN, bruceConfig.bgColor);
    tft.drawString(a.substring(0, a.length() / 2), 10, box_y + 5);
    tft.drawString(a.substring(a.length() / 2),     10, box_y + 17);

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.drawString("user: bruce    any password", 8, 92);

    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.drawString("service live  -  ESC to stop", 8, tftHeight - 14);

    Serial.printf("[TorSSH] .onion: %s\n", addr);
}

// ── Read .onion address from filesystem ────────────────────────────────────────
// Minitor writes <dir>/hostname synchronously before d_setup_onion_service()
// returns.  Use POSIX open() — SD.open() prepends the "/sd" mount point a
// second time (path doubling to /sd/sd/…) and would fail even if the file
// exists.

static bool _read_onion_address(const char *dir) {
    char path[128];
    snprintf(path, sizeof(path), "%s/hostname", dir);

    // Give Minitor daemon ~1 s to finish its burst of fast_list SD reads
    // that happen right after INIT_SERVICE is processed (5 relay lookups for
    // standby + intro-point circuits).  After that window, the daemon is idle
    // or waiting on network, so TFT/SD don't race.
    delay(1000);

    Serial.printf("[TorSSH] POSIX read %s\n", path);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        Serial.printf("[TorSSH] Cannot open hostname errno=%d\n", errno);
        return false;
    }

    ssize_t n = read(fd, g_onion_addr, (ssize_t)sizeof(g_onion_addr) - 1);
    close(fd);

    if (n <= 0) {
        Serial.printf("[TorSSH] hostname read n=%d errno=%d\n", (int)n, errno);
        return false;
    }

    g_onion_addr[n] = '\0';
    while (n > 0 && (g_onion_addr[n-1] == '\n' || g_onion_addr[n-1] == '\r'))
        g_onion_addr[--n] = '\0';

    if (n < 10) {
        Serial.printf("[TorSSH] hostname too short: '%s'\n", g_onion_addr);
        return false;
    }
    return true;
}

// ── SSH server ─────────────────────────────────────────────────────────────────

static bool _handle_ssh_cmd(ssh_session session, ssh_channel ch, const char *cmd) {
    char resp[512];

    if (!cmd || *cmd == '\0') return true;

    if (strncmp(cmd, "help", 4) == 0) {
        snprintf(resp, sizeof(resp),
            "Commands:\r\n"
            "  info           device info\r\n"
            "  wifi           WiFi status\r\n"
            "  onion          show .onion address\r\n"
            "  gpio <n> <v>   set GPIO pin (0/1)\r\n"
            "  adc <n>        read ADC pin\r\n"
            "  gateway <ip> <port> | off   forward .onion to a LAN host\r\n"
            "  reboot         reboot device\r\n"
            "  exit           close session\r\n"
        );
    } else if (strncmp(cmd, "info", 4) == 0) {
        snprintf(resp, sizeof(resp),
            "Bruce-TorSSH | %s\r\nHeap: %lu B | %s | IDF %s\r\n",
            DEVICE_NAME, (unsigned long)ESP.getFreeHeap(),
            ESP.getChipModel(), esp_get_idf_version()
        );
    } else if (strncmp(cmd, "wifi", 4) == 0) {
        snprintf(resp, sizeof(resp),
            "SSID: %s  RSSI: %d dBm  IP: %s\r\n",
            WiFi.SSID().c_str(), WiFi.RSSI(),
            WiFi.localIP().toString().c_str()
        );
    } else if (strncmp(cmd, "onion", 5) == 0) {
        snprintf(resp, sizeof(resp), "%s:22\r\n", g_onion_addr);
    } else if (strncmp(cmd, "gpio ", 5) == 0) {
        int pin, val;
        if (sscanf(cmd + 5, "%d %d", &pin, &val) == 2) {
            pinMode(pin, OUTPUT);
            digitalWrite(pin, val ? HIGH : LOW);
            snprintf(resp, sizeof(resp), "GPIO %d = %d\r\n", pin, val);
        } else {
            snprintf(resp, sizeof(resp), "usage: gpio <pin> <0|1>\r\n");
        }
    } else if (strncmp(cmd, "adc ", 4) == 0) {
        int pin;
        if (sscanf(cmd + 4, "%d", &pin) == 1) {
            snprintf(resp, sizeof(resp), "ADC %d = %d\r\n", pin, analogRead(pin));
        } else {
            snprintf(resp, sizeof(resp), "usage: adc <pin>\r\n");
        }
    } else if (strncmp(cmd, "gateway", 7) == 0) {
        const char *arg = cmd + 7;
        while (*arg == ' ') arg++;
        if (*arg == '\0') {
            // status
            int fd = open(TOR_SSH_FORWARD_CFG, O_RDONLY);
            if (fd >= 0) {
                char b[64] = {0};
                int n = read(fd, b, sizeof(b) - 1);
                close(fd);
                for (int i = 0; i < n; i++) { if (b[i] == '\r' || b[i] == '\n') { b[i] = 0; break; } }
                snprintf(resp, sizeof(resp), "gateway: forward .onion -> %s\r\n", b);
            } else {
                snprintf(resp, sizeof(resp), "gateway: off (local shell)\r\n");
            }
        } else if (strncmp(arg, "off", 3) == 0) {
            remove(TOR_SSH_FORWARD_CFG);
            ssh_channel_write(ch, "gateway off -> rebooting to local shell...\r\n", 43);
            delay(500);
            ESP.restart();
            return false;
        } else {
            char ip[16] = {0};
            int port = 0;
            if (sscanf(arg, "%15[0-9.]:%d", ip, &port) == 2 ||
                sscanf(arg, "%15[0-9.] %d", ip, &port) == 2) {
                int fd = open(TOR_SSH_FORWARD_CFG, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (fd >= 0) {
                    char line[32];
                    int ln = snprintf(line, sizeof(line), "%s:%d\n", ip, port);
                    write(fd, line, ln);
                    fsync(fd);
                    close(fd);
                    char msg[96];
                    int m = snprintf(msg, sizeof(msg),
                                     "gateway -> %s:%d, rebooting to apply...\r\n", ip, port);
                    ssh_channel_write(ch, msg, m);
                    delay(500);
                    ESP.restart();
                    return false;
                } else {
                    snprintf(resp, sizeof(resp), "gateway: cannot write config\r\n");
                }
            } else {
                snprintf(resp, sizeof(resp), "usage: gateway <ip> <port> | gateway off\r\n");
            }
        }
    } else if (strncmp(cmd, "reboot", 6) == 0) {
        ssh_channel_write(ch, "Rebooting...\r\n", 14);
        delay(500);
        ESP.restart();
        return false;
    } else if (strncmp(cmd, "exit", 4) == 0) {
        ssh_channel_write(ch, "Bye.\r\n", 6);
        return false;
    } else {
        snprintf(resp, sizeof(resp), "Unknown: %s\r\n", cmd);
    }

    ssh_channel_write(ch, resp, strlen(resp));
    return true;
}

// Jump-host / port-forward: bridge a client "direct-tcpip" channel to a TCP
// socket on the LAN. Enables `ssh -J bruce@onion user@host`, `ssh -L`, `ssh -D`
// through the board. Target host must be a numeric IP (no DNS on this side).
static void _run_direct_tcpip(ssh_channel ch, const char *host, int port) {
    char logbuf[96];
    snprintf(logbuf, sizeof(logbuf), "[SSH] direct-tcpip -> %s:%d", host ? host : "?", port);
    _sdlog(logbuf);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        ssh_channel_close(ch);
        ssh_channel_free(ch);
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = host ? inet_addr(host) : (uint32_t)0xFFFFFFFFUL;

    if (addr.sin_addr.s_addr == (uint32_t)0xFFFFFFFFUL ||
        connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        _sdlog("[SSH] direct-tcpip connect failed");
        close(sock);
        ssh_channel_send_eof(ch);
        ssh_channel_close(ch);
        ssh_channel_free(ch);
        return;
    }

    int fl = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, fl | O_NONBLOCK);

    uint8_t buf[1024];
    while (!ssh_channel_is_closed(ch)) {
        bool idle = true;

        // client -> target
        int n = ssh_channel_read_timeout(ch, buf, sizeof(buf), 0, 20);
        if (n > 0) {
            send(sock, buf, n, 0);
            idle = false;
        } else if (n == SSH_ERROR) {
            break;
        }
        if (ssh_channel_is_eof(ch)) break;

        // target -> client
        int m = recv(sock, buf, sizeof(buf), 0);
        if (m > 0) {
            ssh_channel_write(ch, buf, m);
            idle = false;
        } else if (m == 0) {
            break; // target closed
        } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
            break;
        }

        if (check(EscPress)) break;
        if (idle) delay(2);
    }

    close(sock);
    ssh_channel_send_eof(ch);
    ssh_channel_close(ch);
    ssh_channel_free(ch);
}

static void _run_session(ssh_session session) {
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        Serial.printf("[TorSSH] key exchange: %s\n", ssh_get_error(session));
        return;
    }

    ssh_message msg;
    bool authed = false;

    // Auth loop — accept password for user "bruce"
    while (!authed) {
        msg = ssh_message_get(session);
        if (!msg) break;
        if (ssh_message_type(msg) == SSH_REQUEST_AUTH &&
            ssh_message_subtype(msg) == SSH_AUTH_METHOD_PASSWORD) {
            if (strcmp(ssh_message_auth_user(msg), "bruce") == 0) {
                ssh_message_auth_reply_success(msg, 0);
                authed = true;
            } else {
                ssh_message_reply_default(msg);
            }
        } else {
            ssh_message_reply_default(msg);
        }
        ssh_message_free(msg);
    }
    if (!authed) return;

    // Channel + shell
    ssh_channel ch = nullptr;
    bool is_tcpip = false;
    char fwd_host[64] = {0};
    int fwd_port = 0;
    while (true) {
        msg = ssh_message_get(session);
        if (!msg) break;
        int type = ssh_message_type(msg);
        int sub  = ssh_message_subtype(msg);
        if (type == SSH_REQUEST_CHANNEL_OPEN && sub == SSH_CHANNEL_SESSION) {
            ch = ssh_message_channel_request_open_reply_accept(msg);
        } else if (type == SSH_REQUEST_CHANNEL_OPEN && sub == SSH_CHANNEL_DIRECT_TCPIP) {
            // Jump host / port forward: client wants a TCP tunnel to host:port.
            const char *dh = ssh_message_channel_request_open_destination(msg);
            fwd_port = ssh_message_channel_request_open_destination_port(msg);
            if (dh) strncpy(fwd_host, dh, sizeof(fwd_host) - 1);
            ch = ssh_message_channel_request_open_reply_accept(msg);
            is_tcpip = true;
            ssh_message_free(msg);
            break;
        } else if (ch && type == SSH_REQUEST_CHANNEL && sub == SSH_CHANNEL_REQUEST_PTY) {
            // Ack the PTY (without implementing real terminal modes) so the client
            // puts its terminal in raw mode and stops local-echoing: the shell loop
            // below is the single echo source. Denying it caused the "PTY
            // allocation request failed" warning and doubled every keystroke.
            ssh_message_channel_request_reply_success(msg);
        } else if (ch && type == SSH_REQUEST_CHANNEL &&
                   (sub == SSH_CHANNEL_REQUEST_SHELL || sub == SSH_CHANNEL_REQUEST_EXEC)) {
            ssh_message_channel_request_reply_success(msg);
            ssh_message_free(msg);
            break;
        } else {
            ssh_message_reply_default(msg);
        }
        ssh_message_free(msg);
    }
    if (!ch) return;

    // A direct-tcpip channel is a tunnel, not a shell: pump bytes and return.
    if (is_tcpip) {
        _run_direct_tcpip(ch, fwd_host, fwd_port);
        return;
    }

    const char *banner = "\r\nBruce-TorSSH v1.0  |  type 'help'\r\n> ";
    ssh_channel_write(ch, banner, strlen(banner));

    // Shell line-edit loop
    char buf[256], line[256] = {0};
    int  lpos = 0;

    while (!ssh_channel_is_closed(ch)) {
        int n = ssh_channel_read_timeout(ch, buf, sizeof(buf) - 1, 0, 100);
        // The session is non-blocking, so SSH_AGAIN (-2) just means "no data
        // within the 100 ms poll window" — keep looping (and poll the device
        // button). Only a real error (SSH_ERROR) or EOF ends the session; the
        // old code treated every n<0 as fatal and dropped the session on the
        // very first idle poll.
        if (n == SSH_AGAIN) {
            if (check(EscPress)) break;
            continue;
        }
        if (n < 0) break;                       // SSH_ERROR
        if (n == 0) {                           // EOF or nothing pending
            if (ssh_channel_is_eof(ch) || check(EscPress)) break;
            continue;
        }
        for (int i = 0; i < n; i++) {
            char c = buf[i];
            if (c == '\r' || c == '\n') {
                line[lpos] = '\0';
                ssh_channel_write(ch, "\r\n", 2);
                if (!_handle_ssh_cmd(session, ch, line)) goto done;
                ssh_channel_write(ch, "> ", 2);
                lpos = 0;
            } else if ((c == 0x7f || c == '\b') && lpos > 0) {
                lpos--;
                ssh_channel_write(ch, "\x08 \x08", 3);
            } else if (lpos < (int)sizeof(line) - 1) {
                line[lpos++] = c;
                ssh_channel_write(ch, &c, 1);
            }
        }
    }

done:
    ssh_channel_send_eof(ch);
    ssh_channel_close(ch);
    ssh_channel_free(ch);
}

// ── Lifecycle ──────────────────────────────────────────────────────────────────

// Firmware build instant, from __DATE__/__TIME__, as a UTC epoch. The device can
// never legitimately run before it was compiled, so this is a hard lower bound on
// any trustworthy clock. Requires TZ to be 0-offset (configTime(0,0,...)) so
// mktime() interprets the build tm as UTC. __TIME__ is the build machine's local
// time, but the day of margin the caller subtracts absorbs that skew.
static time_t _build_epoch() {
    char mon_str[4] = {0};
    int day = 0, year = 0, hh = 0, mm = 0, ss = 0;
    sscanf(__DATE__, "%3s %d %d", mon_str, &day, &year);
    sscanf(__TIME__, "%d:%d:%d", &hh, &mm, &ss);
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char* p = strstr(months, mon_str);
    int mon = p ? (int)((p - months) / 3) : 0;
    struct tm t = {0};
    t.tm_year = year - 1900;
    t.tm_mon = mon;
    t.tm_mday = day;
    t.tm_hour = hh;
    t.tm_min = mm;
    t.tm_sec = ss;
    t.tm_isdst = 0;
    return mktime(&t);
}

static bool _init_tor() {

    _progress(5, "Syncing time...");
    // Minitor derives the HS time period purely from the consensus valid_after and
    // uses time() to reject stale consensus files. A wrong (past) clock makes it
    // accept an expired consensus → descriptor blinded for a past time period →
    // every HSDir returns 400 → service unreachable. A bad NTP reply that still
    // looks plausible (observed: a boot 63 days in the past) sails past a mere
    // "clock != 0" check. So require the clock to reach at least the firmware
    // build date (minus a day of margin for TZ/build skew) before we trust it.
    {
        const time_t floor = _build_epoch() - 86400;  // 1 day of margin
        time_t now = 0;
        bool synced = false;

        configTime(0, 0, "pool.ntp.org", "time.cloudflare.com", "time.google.com");

        for (int i = 0; i < 120; i++) {   // up to ~60 s
            delay(500);
            time(&now);
            if (now >= floor) { synced = true; break; }
            if (i == 60) {                // re-kick SNTP halfway through
                configTime(0, 0, "pool.ntp.org", "time.cloudflare.com", "time.google.com");
            }
        }

        char buf[80];
        snprintf(buf, sizeof(buf), "[TIME] NTP=%lu floor=%lu synced=%d",
                 (unsigned long)now, (unsigned long)floor, synced ? 1 : 0);
        _sdlog(buf);

        if (!synced) {
            // No trustworthy clock: starting anyway would publish a descriptor for
            // the wrong time period and be silently unreachable. Fail loudly instead.
            _sdlog("[TIME] FATAL: no trustworthy clock (NTP failed) — aborting");
            _status("NTP sync failed!", TFT_RED);
            _status("(clock untrusted, retry)", TFT_RED);
            return false;
        }
    }

    // ── Diagnostic 1 : POSIX VFS sur SD ─────────────────────────────────────────
    // Minitor uses open()/write() (not Arduino SD), so the POSIX VFS must work.
    _progress(12, "Testing SD POSIX VFS...");
    mkdir("/sd/tor", 0777);
    {
        int vfd = open("/sd/tor/vfs_test", O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (vfd < 0) {
            char msg[96];
            snprintf(msg, sizeof(msg), "[VFS] FATAL: open() errno=%d", errno);
            _sdlog(msg);
            _status("SD POSIX open FAILED!", TFT_RED);
            _status("(Minitor needs POSIX VFS)", TFT_RED);
            return false;
        }
        write(vfd, "ok", 2);
        close(vfd);
        _sdlog("[VFS] POSIX SD I/O OK");
    }

    // ── Diagnostic 2 : connectivité réseau vers un DA Tor ────────────────────────
    _progress(15, "Testing net to Tor DA...");
    {
        // Try longclaw 199.58.81.140:80 — plain TCP, 10s timeout
        int tsock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (tsock >= 0) {
            struct sockaddr_in ta;
            ta.sin_family = AF_INET;
            ta.sin_port   = htons(80);
            ta.sin_addr.s_addr = inet_addr("199.58.81.140");
            int fl = fcntl(tsock, F_GETFL, 0);
            fcntl(tsock, F_SETFL, fl | O_NONBLOCK);
            ::connect(tsock, (struct sockaddr*)&ta, sizeof(ta));
            fd_set wf; FD_ZERO(&wf); FD_SET(tsock, &wf);
            struct timeval tv = {10, 0};
            int sel = select(tsock + 1, NULL, &wf, NULL, &tv);
            fcntl(tsock, F_SETFL, fl);
            ::close(tsock);
            if (sel <= 0) {
                _sdlog("[NET] FATAL: cannot reach longclaw:80");
                _status("No route to Tor DA!", TFT_RED);
                _status("Check WiFi internet access", TFT_YELLOW);
                return false;
            }
            _sdlog("[NET] longclaw:80 reachable OK");
        }
    }

    _progress(18, "Downloading Tor consensus");
    _status("Takes a few min on first run.", TFT_DARKGREY);
    _status("Serial shows live relay count.", TFT_DARKGREY);
    _status("SD cache speeds up restarts.", TFT_DARKGREY);

    char buf[128];
    snprintf(buf, sizeof(buf), "[TOR] heap before init=%lu", (unsigned long)ESP.getFreeHeap());
    _sdlog(buf);
    _sdlog("[TOR] /sd/tor dir ready");

    esp_task_wdt_delete(NULL);
    _sdlog("[TOR] WDT disabled");

    _sdlog("[TOR] calling d_minitor_INIT...");
    g_tor_in_consensus = true;
    int tor_ret = d_minitor_INIT();
    g_tor_in_consensus = false;

    // Do NOT re-add to WDT — the accept loop never calls esp_task_wdt_reset()
    // so re-adding would cause a WDT reboot after ~5 s of waiting for SSH clients.

    int final_relay_count = g_minitor_relay_count;
    snprintf(buf, sizeof(buf), "[TOR] d_minitor_INIT returned %d relays=%d heap=%lu",
             tor_ret, final_relay_count, (unsigned long)ESP.getFreeHeap());
    _sdlog(buf);

    if (tor_ret < 0) {
        _sdlog("[TOR] FATAL: init failed");
        _status("Tor init failed!", TFT_RED);
        return false;
    }
    _sdlog("[TOR] init OK");

    char relay_buf[48];
    snprintf(relay_buf, sizeof(relay_buf), "Consensus: %d relays", final_relay_count);
    _progress(55, relay_buf);

    _sdlog("[TOR] calling d_setup_onion_service...");
    // Self-heal: if the HS dir exists without key files (left by a previous bad
    // run), remove it so Minitor will regenerate fresh keys.
    {
        struct stat hs_st;
        if (stat(TOR_ONION_DIR, &hs_st) == 0) {
            char key_path[128];
            snprintf(key_path, sizeof(key_path), "%s/private_key_ed25519", TOR_ONION_DIR);
            struct stat key_st;
            if (stat(key_path, &key_st) != 0) {
                _sdlog("[TOR] HS dir stale (no keys) — cleaning up");
                char f[128];
                snprintf(f, sizeof(f), "%s/hostname",            TOR_ONION_DIR); remove(f);
                snprintf(f, sizeof(f), "%s/public_key_ed25519",  TOR_ONION_DIR); remove(f);
                snprintf(f, sizeof(f), "%s/private_key_ed25519", TOR_ONION_DIR); remove(f);
                rmdir(TOR_ONION_DIR);
                _sdlog("[TOR] HS dir removed — Minitor will regenerate");
            } else {
                _sdlog("[TOR] HS dir OK (keys present) — reusing");
            }
        } else {
            _sdlog("[TOR] HS dir not present — Minitor will create");
        }
    }
    // Gateway mode: forward onion:PORT straight to the LAN backend; otherwise
    // forward to the on-device SSH server on loopback.
    int fwd_port = TOR_SSH_LOCAL_PORT;
    if (g_forward_mode) {
        v_set_local_connection_addr(g_forward_ip);
        fwd_port = g_forward_port;
        char fbuf[64];
        snprintf(fbuf, sizeof(fbuf), "[TOR] gateway -> %s:%d", g_forward_ip, g_forward_port);
        _sdlog(fbuf);
    }
    if (d_setup_onion_service(fwd_port, TOR_SSH_ONION_PORT, TOR_ONION_DIR) < 0) {
        fflush(stdout);
        _sdlog("[TOR] FATAL: onion service setup failed");
        _status("Hidden service setup failed!", TFT_RED);
        return false;
    }
    snprintf(buf, sizeof(buf), "[TOR] onion service OK heap=%lu",
             (unsigned long)ESP.getFreeHeap());
    _sdlog(buf);
    Serial.println("[TOR] reading .onion hostname (1 s grace period)...");

    if (!_read_onion_address(TOR_ONION_DIR)) {
        _sdlog("[TOR] FATAL: cannot read .onion hostname");
        // Daemon SD burst is over by now — TFT is safe again
        _status("Cannot read .onion address!", TFT_RED);
        return false;
    }
    _sdlog("[TOR] .onion address read OK");
    return true;
}

static ssh_key g_host_key = nullptr;

static bool _init_ssh() {
    unlink(TOR_LOG_FILE);
    // NOTE: do NOT pre-create TOR_ONION_DIR — Minitor uses stat() to detect
    // whether the HS key directory already exists.  If it does, it skips key
    // generation and tries to load private_key_ed25519 (ENOENT → fatal).
    // Minitor itself creates the dir and writes the keys on first run.

    char buf[128];
    snprintf(buf, sizeof(buf), "[SSH] heap=%lu stack=%u",
             (unsigned long)ESP.getFreeHeap(),
             (unsigned)uxTaskGetStackHighWaterMark(NULL));
    _sdlog(buf);

    // Force-reseed LibSSH's mbedtls DRBG with ESP32 hardware RNG.
    // Without this, entropy collection hangs when wolfSSL is also linked.
    _reseed_ssh_drbg();
    _sdlog("[SSH] DRBG reseeded");

    // Ed25519 keygen hangs when wolfSSL is linked: sha512_init() contends on
    // the ESP32-S3 hardware SHA engine.  ECDSA P256 avoids SHA512 entirely —
    // it uses the DRBG (seeded above with esp_fill_random) and pure-software
    // ECC math, so no hardware contention.
    // Persistent SSH host key.  Reuse the key stored on SD if present so clients
    // don't get a "REMOTE HOST IDENTIFICATION HAS CHANGED" warning after every
    // reboot; only generate on first run.  The key lives unencrypted on the SD
    // card — acceptable here since holding the card == holding the device.
    //
    // We do the file I/O ourselves with POSIX open()/read()/write() and hand
    // libssh only in-memory base64: libssh's fopen()-based ssh_pki_*_file path
    // fails on the ESP-IDF FAT VFS, and its PEM export is a stub in the
    // mbedcrypto backend — only the OpenSSH base64 container is implemented.
    g_host_key = nullptr;
    {
        int kfd = open(TOR_SSH_HOST_KEY, O_RDONLY);
        if (kfd >= 0) {
            char kbuf[2048];
            ssize_t kn = read(kfd, kbuf, sizeof(kbuf) - 1);
            close(kfd);
            if (kn > 0) {
                kbuf[kn] = '\0';
                if (ssh_pki_import_privkey_base64(kbuf, nullptr, nullptr, nullptr, &g_host_key) == SSH_OK
                    && g_host_key) {
                    _sdlog("[SSH] host key loaded from SD");
                    _status("SSH host key loaded", TFT_GREEN);
                } else {
                    g_host_key = nullptr;
                    _sdlog("[SSH] WARN: stored host key invalid — regenerating");
                }
            }
        }
    }

    if (!g_host_key) {
        _status("Generating SSH host key...", TFT_DARKGREY);
        _sdlog("[SSH] keygen ECDSA P256 start");
        ssh_pki_generate(SSH_KEYTYPE_ECDSA_P256, 256, &g_host_key);
        if (!g_host_key) {
            _sdlog("[SSH] FATAL: keygen ECDSA P256 failed");
            _status("Host key error!", TFT_RED);
            return false;
        }
        _sdlog("[SSH] keygen ECDSA P256 OK");

        // Persist for next boot: OpenSSH base64 in memory, then POSIX write.
        // passphrase MUST be NULL, not "": the OpenSSH exporter treats any
        // non-NULL passphrase as "encrypt me" and the bcrypt/AES KDF path is not
        // usable in the mbedcrypto backend, which made the export fail.
        char *b64 = nullptr;
        if (ssh_pki_export_privkey_base64_format(g_host_key, nullptr, nullptr, nullptr,
                                                 &b64, SSH_FILE_FORMAT_OPENSSH) == SSH_OK && b64) {
            int wfd = open(TOR_SSH_HOST_KEY, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (wfd >= 0) {
                size_t blen = strlen(b64);
                bool ok = (write(wfd, b64, blen) == (ssize_t)blen);
                fsync(wfd);
                close(wfd);
                _sdlog(ok ? "[SSH] host key saved to SD" : "[SSH] WARN: host key write failed");
            } else {
                _sdlog("[SSH] WARN: cannot open host key file for write");
            }
            ssh_string_free_char(b64);
        } else {
            _sdlog("[SSH] WARN: host key export failed (regen next boot)");
        }
    }

    snprintf(buf, sizeof(buf), "[SSH] heap after keygen=%lu", (unsigned long)ESP.getFreeHeap());
    _sdlog(buf);

    g_sshbind = ssh_bind_new();
    if (!g_sshbind) {
        _sdlog("[SSH] FATAL: ssh_bind_new failed");
        ssh_key_free(g_host_key); g_host_key = nullptr;
        return false;
    }
    _sdlog("[SSH] bind_new OK");

    ssh_bind_options_set(g_sshbind, SSH_BIND_OPTIONS_IMPORT_KEY, g_host_key);
    const char *bindaddr = "0.0.0.0";
    ssh_bind_options_set(g_sshbind, SSH_BIND_OPTIONS_BINDADDR, bindaddr);
    ssh_bind_options_set(g_sshbind, SSH_BIND_OPTIONS_BINDPORT_STR,
                         String(TOR_SSH_LOCAL_PORT).c_str());
    _sdlog("[SSH] options set");

    if (ssh_bind_listen(g_sshbind) < 0) {
        char errbuf[192];
        snprintf(errbuf, sizeof(errbuf), "[SSH] FATAL: listen failed: %s",
                 ssh_get_error(g_sshbind));
        _sdlog(errbuf);
        ssh_bind_free(g_sshbind); g_sshbind = nullptr;
        return false;
    }
    _sdlog("[SSH] listen OK — server up on port 2222");
    _status("SSH server listening", TFT_GREEN);
    return true;
}

static void _accept_loop() {
    while (true) {
        ssh_session session = ssh_new();
        if (!session) break;

        // Non-blocking accept with 200ms poll via select()
        int      fd = ssh_bind_get_fd(g_sshbind);
        fd_set   fds;
        timeval  tv = {0, 200000};
        FD_ZERO(&fds);
        FD_SET(fd, &fds);

        if (select(fd + 1, &fds, nullptr, nullptr, &tv) > 0 &&
            FD_ISSET(fd, &fds) &&
            ssh_bind_accept(g_sshbind, session) == SSH_OK) {
            _run_session(session);
        }
        ssh_free(session);

        if (check(EscPress)) break;
    }
}

static void _cleanup() {
    if (g_sshbind) {
        // ssh_bind_free() already frees the imported host key (SSH_BIND_OPTIONS_
        // IMPORT_KEY transfers ownership into sshbind->ecdsa), so we must NOT free
        // g_host_key again here — doing so was a double-free that tripped the heap
        // poison assert and crashed on service stop.
        ssh_bind_free(g_sshbind);
        g_sshbind = nullptr;
        g_host_key = nullptr;
    } else if (g_host_key) {
        // No bind was created (early init failure): we still own the key.
        ssh_key_free(g_host_key);
        g_host_key = nullptr;
    }
    // Minitor has no cleanup — daemon stays alive until reboot
    memset(g_onion_addr, 0, sizeof(g_onion_addr));
}

// ── Worker task (stack in PSRAM — internal SRAM exhausted after WiFi) ─────────
// CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM=1 (sdkconfig.h) enables PSRAM stacks.
// Use 64KB from the 8MB PSRAM; TCB stays in internal SRAM (required by FreeRTOS).

static const uint32_t WORKER_STACK_SZ = 64 * 1024;
static StackType_t  *g_worker_stack   = nullptr;
static StaticTask_t *g_worker_tcb     = nullptr;
static volatile bool g_worker_done    = false;

static void _tor_ssh_worker(void *) {
    // Redraw a clean frame — the WiFi selector may have painted over the screen.
    _header("Tor SSH");
    _load_forward_config();

    if (g_forward_mode) {
        // Gateway mode: no on-device SSH server — Minitor relays each .onion
        // stream to the LAN backend. Bring up Tor and stay alive while its own
        // tasks do the forwarding; the button stops it.
        if (_init_tor()) {
            _show_onion(g_onion_addr);
            while (!check(EscPress)) delay(200);
        } else {
            delay(3000);
        }
    } else if (_init_ssh()) {
        if (_init_tor()) {
            _show_onion(g_onion_addr);
            _accept_loop();
        } else {
            delay(3000);
        }
    } else {
        _status("SSH bind failed!", TFT_RED);
        delay(2500);
    }
    _sdlog("[END] cleanup");
    _cleanup();
    _header("Tor SSH");
    _status("Stopped.", TFT_DARKGREY);
    g_worker_done = true;
    vTaskDelete(NULL);
}

// ── Public entry point ─────────────────────────────────────────────────────────

// On-device mode picker shown when the Tor SSH app starts. Returns false if the
// user backs out. Writes/removes the gateway config (forward.txt); the worker
// reads it at startup to pick local-shell vs gateway mode.
static bool _select_tor_mode() {
    _load_forward_config();

    bool proceed = false;
    std::vector<Option> options;

    options.push_back({"Local shell", [&]() {
        remove(TOR_SSH_FORWARD_CFG);
        proceed = true;
    }});

    String gwLabel = g_forward_mode
        ? (String("Gateway ") + g_forward_ip + ":" + String(g_forward_port))
        : String("Gateway -> PC...");
    options.push_back({gwLabel.c_str(), [&]() {
        String def = g_forward_mode
            ? (String(g_forward_ip) + ":" + String(g_forward_port))
            : String("192.168.1.10:22");
        String in = keyboard(def, 21, "Backend IP:PORT");
        char ip[16] = {0};
        int port = 0;
        if (sscanf(in.c_str(), "%15[0-9.]:%d", ip, &port) == 2 && port > 0 && port < 65536) {
            int fd = open(TOR_SSH_FORWARD_CFG, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd >= 0) {
                char l[32];
                int n = snprintf(l, sizeof(l), "%s:%d\n", ip, port);
                write(fd, l, n);
                fsync(fd);
                close(fd);
                proceed = true;
            } else {
                _status("Cannot write config", TFT_RED);
                delay(1500);
            }
        } else {
            _status("Bad IP:PORT", TFT_RED);
            delay(1500);
        }
    }});

    options.push_back({"Back", [&]() { proceed = false; }});

    loopOptions(options, MENU_TYPE_SUBMENU, "Tor Mode");
    return proceed;
}

void tor_ssh_menu() {
    _header("Tor SSH");

    setupSdCard();
    mkdir("/sd/tor_ssh", 0777);
    mkdir("/sd/tor",     0777);
    // POSIX log init — SD.open() path-doubles the mount prefix (/sd/sd/…)
    unlink(TOR_LOG_FILE);
    {
        int lfd = open(TOR_LOG_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (lfd >= 0) {
            write(lfd, "[BOOT] tor_ssh_menu entered\n", 28);
            close(lfd);
        }
    }

    // Mode picker: local shell vs gateway-to-LAN. Writes forward.txt; the worker
    // reads it below. Backing out returns to the Others menu.
    if (!_select_tor_mode()) return;

    // WiFi — low stack, fine in main task
    _sdlog("[WIFI] checking...");
    if (WiFi.status() != WL_CONNECTED) {
        _status("No WiFi — opening selector...", TFT_YELLOW);
        delay(800);
        if (!wifiConnectMenu(WIFI_MODE_STA)) {
            _sdlog("[WIFI] FATAL: connection failed");
            _status("WiFi failed. Abort.", TFT_RED);
            delay(2000);
            return;
        }
    }
    {
        char buf[64];
        snprintf(buf, sizeof(buf), "[WIFI] OK ip=%s", WiFi.localIP().toString().c_str());
        _sdlog(buf);
    }
    {
        char ipmsg[48];
        snprintf(ipmsg, sizeof(ipmsg), "WiFi OK: %s", WiFi.localIP().toString().c_str());
        _status(ipmsg, TFT_GREEN);
    }

    // Allocate 64KB worker stack in PSRAM — WiFi driver has claimed most internal
    // SRAM (~50KB DMA buffers), so even 24KB xTaskCreate fails at this point.
    // TCB must be in internal SRAM (FreeRTOS requirement).
    g_worker_done  = false;
    g_worker_stack = (StackType_t *)heap_caps_malloc(WORKER_STACK_SZ, MALLOC_CAP_SPIRAM);
    g_worker_tcb   = (StaticTask_t *)heap_caps_malloc(sizeof(StaticTask_t),
                                     MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!g_worker_stack || !g_worker_tcb) {
        _sdlog("[FATAL] PSRAM stack alloc failed");
        _status("Task alloc failed!", TFT_RED);
        if (g_worker_stack) { heap_caps_free(g_worker_stack); g_worker_stack = nullptr; }
        if (g_worker_tcb)   { heap_caps_free(g_worker_tcb);   g_worker_tcb   = nullptr; }
        delay(3000);
        return;
    }
    {
        char buf[80];
        snprintf(buf, sizeof(buf), "[TASK] PSRAM stack @%p size=%lu",
                 g_worker_stack, (unsigned long)WORKER_STACK_SZ);
        _sdlog(buf);
    }
    TaskHandle_t handle = xTaskCreateStaticPinnedToCore(
        _tor_ssh_worker, "torssh",
        WORKER_STACK_SZ / sizeof(StackType_t),
        nullptr, 1,
        g_worker_stack, g_worker_tcb, 1
    );
    if (!handle) {
        _sdlog("[FATAL] xTaskCreateStatic failed");
        _status("Task create failed!", TFT_RED);
        heap_caps_free(g_worker_stack); g_worker_stack = nullptr;
        heap_caps_free(g_worker_tcb);   g_worker_tcb   = nullptr;
        delay(3000);
        return;
    }
    _sdlog("[TASK] worker spawned");

    // Main task polls until worker finishes (ESC handled inside _accept_loop).
    // NOTE: no TFT writes here — TFT (SPI) and SD-POSIX (SPI) share the same
    // hardware bus but different driver mutexes; concurrent access crashes the bus.
    int last_relay_logged = -1;
    while (!g_worker_done) {
        delay(100);
        if (g_tor_in_consensus) {
            int cnt = g_minitor_relay_count;
            if (cnt - last_relay_logged >= 500) {
                last_relay_logged = cnt;
                Serial.printf("[TOR] consensus: %d relays\n", cnt);
            }
        }
    }
    // Free PSRAM stack after worker exits
    if (g_worker_stack) { heap_caps_free(g_worker_stack); g_worker_stack = nullptr; }
    if (g_worker_tcb)   { heap_caps_free(g_worker_tcb);   g_worker_tcb   = nullptr; }
    delay(500);
}

#endif // LITE_VERSION
