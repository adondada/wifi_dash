# 📶 Wi-Fi Dash (Pwnagotchi Plugin)

A clean, iOS-style Wi-Fi dashboard for Pwnagotchi. It shows **live networks**, lets you **whitelist** quickly, reads your **WPA-Sec** cracked results (API key only), keeps **history**, manages **wordlists**, and can **package handshakes + wordlists** into a tarball for offline cracking on your own machine.

> This plugin **does not perform on-device brute-force or active attacks**. It only prepares artifacts (pcaps + wordlists) so you can crack legally on your own hardware/tools.

---

## Features

- **Live networks:** ESSID, BSSID, channel, RSSI bars.
- **One-click whitelist:** Add/remove directly from the list.
- **WPA-Sec results:** Reads cracked entries from wpa-sec via API key; no username required.
- **History:** Persisted catalog of seen BSSIDs.
- **Wordlists:** Upload/delete wordlists, keep them across reboots.
- **“Ready for cracking” packages:** Build `tar.gz` bundles with handshakes + chosen wordlist for offline cracking (Hashcat/Aircrack/Hashtopolis on your own gear).
- **Debug panel:** Shows last agent payload keys so you can confirm where AP data comes from.

---

## Requirements

- Pwnagotchi (community builds incl. **jayofelony** are fine).
- Bettercap already provided by the image.
- Python3 standard libs (plus `requests` recommended for WPA-Sec API).
- WPA-Sec **API key** if you want cracked-password sync (no username).  
  Get one at <https://wpa-sec.stanev.org/> (top-right “API key”).

---

## How it works (short)

- The plugin listens to multiple runtime signals (`on_wifi_update`, `on_unfiltered_ap_list`, `on_handshake`) because different images expose AP lists in slightly different shapes. It normalizes them and renders a single dashboard.
- WPA-Sec: sends a GET with header `API-Key: <your_key>` and shows any cracked entries returned.
- Packaging: searches common handshake folders, plus any path remembered in the history entry for a BSSID, then bundles matches with your selected wordlist.

---

## Screenshots

Add your own later:

- `assets/dashboard.png`
- `assets/wpasec.png`
- `assets/history.png`

---

## Configuration keys recognized

- `main.custom_plugins` — absolute path of your custom plugin folder (standard Pwnagotchi mechanism).  
- `main.plugins.wifi_dash.enabled = true`
- WPA-Sec (optional; the dash will also read an existing key if the stock `wpa-sec` plugin is already configured):
  - `main.plugins.wpa-sec.enabled = true`
  - `main.plugins.wpa-sec.api_key = "YOUR_API_KEY"`

---

## FAQ

**Q: Why are live networks empty?**  
A: Open the page bottom **Debug** panel. If your image exposes APs under a different field, the panel shows which keys are present. The parser already handles common shapes, but if you see something exotic, open an issue with that snippet.

**Q: Where are handshakes stored?**  
A: The packager searches typical locations like `/root/handshakes`, `/var/lib/pwnagotchi/handshakes`, `/root/pcaps`, etc., and any explicit file path captured in history.

**Q: Does this upload to WPA-Sec?**  
A: The dash only **reads** cracked results. Uploading is handled by the stock `wpa-sec` plugin if you enable it and set its key.

**Q: Can it crack on the device?**  
A: No. It prepares bundles for **offline cracking** on your machine. That keeps things legal, safer, and avoids cooking the Pi.

---

## Uninstall / Update

- **Update:** `cd /usr/local/share/pwnagotchi/custom-plugins/wifi_dash && sudo git pull && sudo systemctl restart pwnagotchi`
- **Disable:** set `main.plugins.wifi_dash.enabled = false` and restart.
- **Remove:** `sudo rm -rf /usr/local/share/pwnagotchi/custom-plugins/wifi_dash`

---

## License

MIT

---

## Credits

- Pwnagotchi project & community.  
- WPA-Sec (read-only API integration).  

---

## 📦 One-Shot Install (copy-paste everything below)

> This single block clones the plugin into your **custom plugins** folder, enables it, ensures the custom plugins path is set, and configures WPA-Sec (optional). It restarts the service and prints how to open the page.

```bash
set -e

# 0) Paths / names
PLUGIN_NAME="wifi_dash"
CUSTOM_DIR="/usr/local/share/pwnagotchi/custom-plugins"
PLUGIN_DIR="$CUSTOM_DIR/$PLUGIN_NAME"
REPO_URL="https://github.com/YOUR-USERNAME/YOUR-REPO"   # <-- change to your repo

# 1) Make sure custom plugins dir exists
sudo mkdir -p "$CUSTOM_DIR"

# 2) Get or update the plugin
if [ -d "$PLUGIN_DIR/.git" ]; then
  echo "[*] Updating $PLUGIN_NAME in $PLUGIN_DIR"
  cd "$PLUGIN_DIR" && sudo git pull --ff-only
else
  echo "[*] Cloning $PLUGIN_NAME into $PLUGIN_DIR"
  sudo git clone "$REPO_URL" "$PLUGIN_DIR"
fi

# 3) Optional: install Python dependency for WPA-Sec API read (requests)
# (Most images already have it; harmless if reinstalled)
sudo python3 - <<'PY'
import sys, subprocess
try:
  import requests  # noqa
except Exception:
  subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
PY

# 4) Ensure main.custom_plugins is set; append if missing
CFG="/etc/pwnagotchi/config.toml"
sudo touch "$CFG"
if ! sudo grep -q '^main.custom_plugins' "$CFG" ; then
  echo '[*] Adding main.custom_plugins to config.toml'
  echo 'main.custom_plugins = "/usr/local/share/pwnagotchi/custom-plugins"' | sudo tee -a "$CFG" >/dev/null
fi

# 5) Enable the plugin and (optionally) WPA-Sec section
#    Safe to append; TOML reads the last occurrence if duplicated in many builds.
echo "[*] Enabling $PLUGIN_NAME in config.toml"
sudo tee -a "$CFG" >/dev/null <<'TOML'

# --- Wi-Fi Dash plugin ---
main.plugins.wifi_dash.enabled = true

# --- WPA-Sec (optional; API key only, no username) ---
# If you already use the stock wpa-sec plugin, keep your existing settings.
# The dash will read main.plugins.wpa-sec.api_key automatically.
# Uncomment and set only if you haven't configured wpa-sec yet:
# main.plugins.wpa-sec.enabled = true
# main.plugins.wpa-sec.api_key = "PUT-YOUR-WPASEC-API-KEY-HERE"
TOML

# 6) Restart pwnagotchi to load the plugin
echo "[*] Restarting pwnagotchi"
sudo systemctl restart pwnagotchi

# 7) Tell the user where to click
echo
echo "Done."
echo "Open: http://pwnagotchi.local/plugins/wifi_dash   (or http://<device-ip>/plugins/wifi_dash)"
echo
echo "Tip: If the Live Networks panel is empty, scroll to the bottom Debug section and check the agent keys."
