#if !defined(LITE_VERSION)

#include "tor_ssh.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/settings.h"
#include "core/utils.h"
#include "core/wifi/wifi_common.h"

#include <SD.h>
#include <WiFi.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

extern "C" {
#include "minitor.h"
}

// ── Configuration ──────────────────────────────────────────────────────────────

// SSH port exposed on the .onion address
#define TOR_SSH_ONION_PORT  22
// Local port the SSH server binds to on loopback — Minitor proxies this
#define TOR_SSH_LOCAL_PORT  2222
// SD card path used for Tor consensus cache + HS keys
// Must match FILESYSTEM_PREFIX in Minitor's config.h
// Bruce mounts the SD at /sd via SD.begin(..., "/sd", ...)
#define TOR_ONION_DIR       "/sd/tor_ssh"
// SSH host key file (persisted on SD — generated once)
#define TOR_SSH_HOST_KEY    "/sd/tor_ssh/ssh_host_rsa_key"

// ── Internal state ─────────────────────────────────────────────────────────────

static char     g_onion_addr[70]  = {0};
static ssh_bind g_sshbind          = nullptr;

// ── Display helpers ────────────────────────────────────────────────────────────

static void _header(const char *title) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.drawCentreString(title, tftWidth / 2, 4, 1);
    tft.drawLine(0, 20, tftWidth, 20, bruceConfig.priColor);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(4, 26);
}

static void _status(const char *msg, uint16_t color = TFT_WHITE) {
    tft.setTextColor(color, bruceConfig.bgColor);
    tft.println(msg);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
}

static void _progress(uint8_t pct, const char *label) {
    int bar_y  = tftHeight - 24;
    int bar_w  = tftWidth - 16;
    int fill_w = (bar_w * pct) / 100;

    tft.fillRect(8, bar_y, bar_w, 12, bruceConfig.bgColor);
    tft.drawRect(8, bar_y, bar_w, 12, bruceConfig.priColor);
    if (fill_w > 0)
        tft.fillRect(9, bar_y + 1, fill_w - 1, 10, bruceConfig.priColor);

    tft.fillRect(0, bar_y - 14, tftWidth, 12, bruceConfig.bgColor);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setCursor(8, bar_y - 12);
    tft.print(label);
}

static void _show_onion(const char *addr) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.drawCentreString("Tor SSH Ready", tftWidth / 2, 4, 1);
    tft.drawLine(0, 20, tftWidth, 20, bruceConfig.priColor);

    tft.setTextSize(FP);
    tft.setCursor(4, 28);
    tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
    tft.println("ssh bruce@");

    // Split .onion across two lines for the narrow 170px display
    String a = String(addr);
    tft.setTextColor(TFT_CYAN, bruceConfig.bgColor);
    tft.println(a.substring(0, a.length() / 2));
    tft.println(a.substring(a.length() / 2));

    tft.println();
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.println("port: 22  user: bruce");
    tft.println();
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.println("ESC = stop");

    Serial.printf("[TorSSH] .onion: %s\n", addr);
}

// ── Read .onion address from filesystem ────────────────────────────────────────
// Minitor writes <dir>/hostname after d_setup_onion_service() returns.

static bool _read_onion_address(const char *dir) {
    char path[128];
    snprintf(path, sizeof(path), "%s/hostname", dir);

    // Small delay to ensure Minitor has flushed the file
    delay(500);

    File f = SD.open(path, FILE_READ);
    if (!f) {
        Serial.printf("[TorSSH] Cannot open %s\n", path);
        return false;
    }

    size_t n = f.readBytes(g_onion_addr, sizeof(g_onion_addr) - 1);
    f.close();

    g_onion_addr[n] = '\0';
    // Strip trailing newline if any
    while (n > 0 && (g_onion_addr[n-1] == '\n' || g_onion_addr[n-1] == '\r'))
        g_onion_addr[--n] = '\0';

    if (n < 10) {
        Serial.printf("[TorSSH] Hostname file too short: '%s'\n", g_onion_addr);
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
    while (true) {
        msg = ssh_message_get(session);
        if (!msg) break;
        int type = ssh_message_type(msg);
        int sub  = ssh_message_subtype(msg);
        if (type == SSH_REQUEST_CHANNEL_OPEN && sub == SSH_CHANNEL_SESSION) {
            ch = ssh_message_channel_request_open_reply_accept(msg);
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

    const char *banner = "\r\nBruce-TorSSH v1.0  |  type 'help'\r\n> ";
    ssh_channel_write(ch, banner, strlen(banner));

    // Shell line-edit loop
    char buf[256], line[256] = {0};
    int  lpos = 0;

    while (!ssh_channel_is_closed(ch)) {
        int n = ssh_channel_read_timeout(ch, buf, sizeof(buf) - 1, 0, 100);
        if (n < 0) break;
        if (n == 0) {
            if (check(EscPress)) break;
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

static bool _init_tor() {
    // Ensure data directory exists
    if (!SD.exists(TOR_ONION_DIR)) SD.mkdir(TOR_ONION_DIR);

    _progress(5, "Connecting to Tor network...");
    _status("First run ~5 min (consensus fetch)", TFT_DARKGREY);
    _status("Faster on restart (cached on SD)", TFT_DARKGREY);

    if (d_minitor_INIT() < 0) {
        _status("Tor init failed!", TFT_RED);
        return false;
    }
    _progress(55, "Building circuits...");

    if (d_setup_onion_service(TOR_SSH_LOCAL_PORT, TOR_SSH_ONION_PORT, TOR_ONION_DIR) < 0) {
        _status("Hidden service setup failed!", TFT_RED);
        return false;
    }
    _progress(85, "Registering hidden service...");

    if (!_read_onion_address(TOR_ONION_DIR)) {
        _status("Cannot read .onion address!", TFT_RED);
        return false;
    }
    _progress(100, "Hidden service online!");
    return true;
}

static bool _init_ssh() {
    g_sshbind = ssh_bind_new();
    if (!g_sshbind) return false;

    const char *bindaddr = "127.0.0.1";
    ssh_bind_options_set(g_sshbind, SSH_BIND_OPTIONS_BINDADDR, bindaddr);
    ssh_bind_options_set(g_sshbind, SSH_BIND_OPTIONS_BINDPORT_STR,
                         String(TOR_SSH_LOCAL_PORT).c_str());
    ssh_bind_options_set(g_sshbind, SSH_BIND_OPTIONS_HOSTKEY, TOR_SSH_HOST_KEY);

    if (ssh_bind_listen(g_sshbind) < 0) {
        Serial.printf("[TorSSH] listen failed: %s\n", ssh_get_error(g_sshbind));
        ssh_bind_free(g_sshbind);
        g_sshbind = nullptr;
        return false;
    }
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
        ssh_bind_free(g_sshbind);
        g_sshbind = nullptr;
    }
    // Minitor has no cleanup — daemon stays alive until reboot
    memset(g_onion_addr, 0, sizeof(g_onion_addr));
}

// ── Public entry point ─────────────────────────────────────────────────────────

void tor_ssh_menu() {
    _header("Tor SSH");

    // 1. WiFi
    if (WiFi.status() != WL_CONNECTED) {
        _status("No WiFi — opening selector...", TFT_YELLOW);
        delay(800);
        if (!wifiConnectMenu(WIFI_MODE_STA)) {
            _status("WiFi failed. Abort.", TFT_RED);
            delay(2000);
            return;
        }
    }
    tft.print("WiFi: ");
    tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
    tft.println(WiFi.localIP().toString());
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);

    // 2. SSH server (bind first so it's ready when Tor connects)
    if (!_init_ssh()) {
        _status("SSH bind failed!", TFT_RED);
        delay(2500);
        return;
    }

    // 3. Tor init (blocks until circuit + HS ready)
    if (!_init_tor()) {
        delay(3000);
        _cleanup();
        return;
    }

    // 4. Show address + run accept loop
    _show_onion(g_onion_addr);
    _accept_loop();

    // 5. Teardown
    _cleanup();
    _header("Tor SSH");
    _status("Stopped.", TFT_DARKGREY);
    delay(1500);
}

#endif // LITE_VERSION
