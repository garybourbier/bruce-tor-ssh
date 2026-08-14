#if !defined(LITE_VERSION)

#include "tor_ssh.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/settings.h"
#include "core/utils.h"
#include "core/wifi/wifi_common.h"

#include <WiFi.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

extern "C" {
#include "minitor.h"
}

// ── Configuration ──────────────────────────────────────────────────────────────

#define TOR_SSH_PORT       22       // SSH port exposed on the .onion
#define TOR_SSH_LOCAL_PORT 2222     // localhost port the SSH server binds to
#define TOR_ONION_DIR      "/sd/tor_ssh"  // consensus + HS keys on SD

// ── Internal state ─────────────────────────────────────────────────────────────

static enum {
    STATE_IDLE,
    STATE_WIFI_CHECK,
    STATE_TOR_INIT,
    STATE_TOR_READY,
    STATE_SSH_RUNNING,
    STATE_STOPPING,
} g_state = STATE_IDLE;

static char     g_onion_addr[70] = {0};
static ssh_bind g_sshbind         = nullptr;
static bool     g_tor_started     = false;

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

static void _progress_bar(uint8_t pct, const char *label) {
    int bar_y    = tftHeight - 24;
    int bar_w    = tftWidth - 16;
    int fill_w   = (bar_w * pct) / 100;

    tft.fillRect(8, bar_y, bar_w, 12, bruceConfig.bgColor);
    tft.drawRect(8, bar_y, bar_w, 12, bruceConfig.priColor);
    if (fill_w > 0)
        tft.fillRect(9, bar_y + 1, fill_w - 1, 10, bruceConfig.priColor);

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setCursor(8, bar_y - 12);
    tft.fillRect(0, bar_y - 14, tftWidth, 12, bruceConfig.bgColor);
    tft.print(label);
}

static void _show_onion(const char *addr) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.drawCentreString("Tor SSH Ready", tftWidth / 2, 4, 1);
    tft.drawLine(0, 20, tftWidth, 20, bruceConfig.priColor);

    tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setCursor(4, 28);
    tft.println("Connect via Tor Browser:");
    tft.println();

    // .onion address split across lines for narrow display
    String a = String(addr);
    int half = a.length() / 2;
    tft.setTextColor(TFT_CYAN, bruceConfig.bgColor);
    tft.println(a.substring(0, half));
    tft.println(a.substring(half));

    tft.println();
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.println("SSH port : 22");
    tft.println("User     : bruce");
    tft.println();
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.println("ESC = stop");

    // Mirror address to serial for convenience
    Serial.printf("[TorSSH] .onion: %s\n", addr);
}

// ── SSH server ─────────────────────────────────────────────────────────────────

// Simple command dispatcher run after SSH authentication succeeds.
// Returns false when the session should close.
static bool _handle_ssh_command(ssh_session session, ssh_channel channel, const char *cmd) {
    char resp[512];

    if (!cmd || strlen(cmd) == 0) return true;

    if (strncmp(cmd, "help", 4) == 0) {
        snprintf(resp, sizeof(resp),
            "Commands:\r\n"
            "  help          this menu\r\n"
            "  info          device info\r\n"
            "  wifi          WiFi status\r\n"
            "  onion         show .onion address\r\n"
            "  gpio <n> <v>  set GPIO pin (0/1)\r\n"
            "  adc <n>       read ADC pin\r\n"
            "  reboot        reboot device\r\n"
            "  exit          close session\r\n"
        );
    } else if (strncmp(cmd, "info", 4) == 0) {
        snprintf(resp, sizeof(resp),
            "Bruce-TorSSH on %s\r\n"
            "Free heap : %lu bytes\r\n"
            "Chip model: %s\r\n"
            "IDF ver   : %s\r\n",
            DEVICE_NAME,
            (unsigned long)ESP.getFreeHeap(),
            ESP.getChipModel(),
            esp_get_idf_version()
        );
    } else if (strncmp(cmd, "wifi", 4) == 0) {
        snprintf(resp, sizeof(resp),
            "SSID : %s\r\nRSSI : %d dBm\r\nIP   : %s\r\n",
            WiFi.SSID().c_str(),
            WiFi.RSSI(),
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
        ssh_channel_write(channel, "Rebooting...\r\n", 14);
        delay(500);
        ESP.restart();
        return false;
    } else if (strncmp(cmd, "exit", 4) == 0) {
        ssh_channel_write(channel, "Bye.\r\n", 6);
        return false;
    } else {
        snprintf(resp, sizeof(resp), "Unknown command: %s\r\n", cmd);
    }

    ssh_channel_write(channel, resp, strlen(resp));
    return true;
}

// Handles one SSH session: auth → channel → shell loop.
static void _run_ssh_session(ssh_session session) {
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        Serial.printf("[TorSSH] key exchange failed: %s\n", ssh_get_error(session));
        return;
    }

    // Auth: accept any password (hidden service is the security layer)
    ssh_message msg;
    bool authed = false;
    while (!authed) {
        msg = ssh_message_get(session);
        if (!msg) break;
        if (ssh_message_type(msg) == SSH_REQUEST_AUTH &&
            ssh_message_subtype(msg) == SSH_AUTH_METHOD_PASSWORD) {
            // Only accept user "bruce"
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

    // Wait for channel + shell request
    ssh_channel channel = nullptr;
    while (true) {
        msg = ssh_message_get(session);
        if (!msg) break;
        if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(msg) == SSH_CHANNEL_SESSION) {
            channel = ssh_message_channel_request_open_reply_accept(msg);
        } else if (channel && ssh_message_type(msg) == SSH_REQUEST_CHANNEL) {
            if (ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_SHELL ||
                ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_EXEC) {
                ssh_message_channel_request_reply_success(msg);
                ssh_message_free(msg);
                break;
            }
        }
        ssh_message_reply_default(msg);
        ssh_message_free(msg);
    }

    if (!channel) return;

    const char *banner = "Bruce-TorSSH v1.0\r\nType 'help' for commands.\r\n> ";
    ssh_channel_write(channel, banner, strlen(banner));

    // Shell read loop
    char buf[256];
    char line[256] = {0};
    int  lpos       = 0;

    while (!ssh_channel_is_closed(channel)) {
        int n = ssh_channel_read_timeout(channel, buf, sizeof(buf) - 1, 0, 100);
        if (n < 0) break;
        if (n == 0) {
            if (check(EscPress)) break;
            continue;
        }

        for (int i = 0; i < n; i++) {
            char c = buf[i];
            if (c == '\r' || c == '\n') {
                line[lpos] = '\0';
                ssh_channel_write(channel, "\r\n", 2);
                if (!_handle_ssh_command(session, channel, line)) goto session_done;
                ssh_channel_write(channel, "> ", 2);
                lpos = 0;
            } else if (c == 0x7f || c == 0x08) { // backspace
                if (lpos > 0) {
                    lpos--;
                    ssh_channel_write(channel, "\x08 \x08", 3);
                }
            } else if (lpos < (int)sizeof(line) - 1) {
                line[lpos++] = c;
                ssh_channel_write(channel, &c, 1); // echo
            }
        }
    }

session_done:
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
}

// ── Tor + SSH lifecycle ────────────────────────────────────────────────────────

static bool _init_tor() {
    _status("Fetching Tor consensus...", TFT_YELLOW);
    _progress_bar(5, "Connecting to Tor network...");

    // Ensure the HS data directory exists on SD
    if (!SD.exists(TOR_ONION_DIR)) {
        SD.mkdir(TOR_ONION_DIR);
    }

    // Minitor init — blocks ~300 sec on first run, faster if consensus cached
    if (d_minitor_INIT() != 0) {
        _status("Minitor init failed!", TFT_RED);
        return false;
    }
    _progress_bar(60, "Building circuits...");
    _status("Tor circuits ready", TFT_GREEN);

    // Register the hidden service: local SSH port → .onion:22
    if (d_setup_onion_service(TOR_SSH_LOCAL_PORT, TOR_SSH_PORT, TOR_ONION_DIR) != 0) {
        _status("Hidden service setup failed!", TFT_RED);
        return false;
    }
    _progress_bar(90, "Registering hidden service...");

    // Read back the generated .onion address
    const char *addr = d_minitor_get_onion_address(TOR_ONION_DIR);
    if (!addr) {
        _status("Could not read .onion address!", TFT_RED);
        return false;
    }
    strlcpy(g_onion_addr, addr, sizeof(g_onion_addr));
    _progress_bar(100, "Hidden service online!");

    g_tor_started = true;
    return true;
}

static bool _init_ssh_server() {
    g_sshbind = ssh_bind_new();
    if (!g_sshbind) return false;

    // Host key is generated once and stored on SD
    const char *host_key = "/sd/tor_ssh/ssh_host_rsa_key";

    ssh_bind_options_set(g_sshbind, SSH_BIND_OPTIONS_HOSTKEY, host_key);
    ssh_bind_options_set(g_sshbind, SSH_BIND_OPTIONS_BINDPORT_STR,
                         String(TOR_SSH_LOCAL_PORT).c_str());

    // Bind only on loopback — Minitor does the .onion proxying
    const char *bindaddr = "127.0.0.1";
    ssh_bind_options_set(g_sshbind, SSH_BIND_OPTIONS_BINDADDR, bindaddr);

    if (ssh_bind_listen(g_sshbind) < 0) {
        Serial.printf("[TorSSH] ssh_bind_listen: %s\n", ssh_get_error(g_sshbind));
        ssh_bind_free(g_sshbind);
        g_sshbind = nullptr;
        return false;
    }

    _status("SSH server listening", TFT_GREEN);
    return true;
}

static void _accept_loop() {
    while (g_state == STATE_SSH_RUNNING) {
        // Non-blocking accept with 200ms poll
        ssh_session session = ssh_new();
        if (!session) break;

        struct timeval tv = {0, 200000};
        int fd = ssh_bind_get_fd(g_sshbind);
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);

        int ready = select(fd + 1, &fds, nullptr, nullptr, &tv);
        if (ready > 0 && FD_ISSET(fd, &fds)) {
            if (ssh_bind_accept(g_sshbind, session) == SSH_OK) {
                _run_ssh_session(session);
            }
        }
        ssh_free(session);

        if (check(EscPress)) {
            g_state = STATE_STOPPING;
            break;
        }
    }
}

static void _cleanup() {
    if (g_sshbind) {
        ssh_bind_free(g_sshbind);
        g_sshbind = nullptr;
    }
    if (g_tor_started) {
        d_minitor_cleanup();
        g_tor_started = false;
    }
    memset(g_onion_addr, 0, sizeof(g_onion_addr));
    g_state = STATE_IDLE;
}

// ── Public entry point ─────────────────────────────────────────────────────────

void tor_ssh_menu() {
    _header("Tor SSH");

    // 1. WiFi check
    g_state = STATE_WIFI_CHECK;
    if (WiFi.status() != WL_CONNECTED) {
        _status("WiFi not connected.", TFT_YELLOW);
        _status("Opening WiFi menu...");
        delay(1000);
        if (!wifiConnectMenu(WIFI_MODE_STA)) {
            _status("WiFi failed. Aborting.", TFT_RED);
            delay(2000);
            return;
        }
    }
    _status("WiFi OK: ", TFT_GREEN);
    tft.println(WiFi.localIP().toString());

    // 2. Tor init
    g_state = STATE_TOR_INIT;
    _status("Starting Tor (this takes ~5 min)");
    _status("Saved consensus speeds up restart", TFT_DARKGREY);

    if (!_init_tor()) {
        delay(3000);
        _cleanup();
        return;
    }

    // 3. SSH server
    if (!_init_ssh_server()) {
        _status("SSH server failed!", TFT_RED);
        delay(3000);
        _cleanup();
        return;
    }

    // 4. Show .onion + run accept loop
    g_state = STATE_SSH_RUNNING;
    _show_onion(g_onion_addr);

    _accept_loop();

    // 5. Teardown
    _cleanup();
    _header("Tor SSH");
    _status("Stopped.", TFT_DARKGREY);
    delay(1500);
}

#endif // LITE_VERSION
