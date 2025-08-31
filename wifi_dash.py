# wifi_dash.py
# wifi dashboard plugin for pwnagotchi (full)
# shows live networks, whitelist, history, wpasec cracked results
# allows upload/delete of wordlists and packages handshake+wordlist for offline cracking
# does NOT run any brute force or attack on device

import os
import json
import time
import logging
import shutil
import tarfile
from datetime import datetime

# toml fallback for reading config file
try:
    import tomllib as toml
except:
    try:
        import tomli as toml
    except:
        toml = None

# requests used only to fetch wpa-sec read-only results
try:
    import requests
except:
    requests = None

import pwnagotchi.plugins as plugins

# ----------------------------
# small helpers
# ----------------------------
def _now():
    return int(time.time())

def _ts(ts):
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(ts)

def _safe(x):
    return "" if x is None else str(x)

def _rssi_bucket(rssi):
    try:
        r = int(rssi)
    except:
        return 0
    if r >= -55: return 4
    if r >= -65: return 3
    if r >= -75: return 2
    return 1

def _bars(n):
    return "▁▂▃▄▅▆▇"[max(0, min(5, n))] * min(4, max(0, n))

def _ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        logging.debug("wifi_dash _ensure_dir: %s", e)

def _load(path, default):
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
    except Exception as e:
        logging.debug("wifi_dash _load %s: %s", path, e)
    return default

def _save(path, obj):
    try:
        with open(path, "w") as f:
            json.dump(obj, f, indent=2)
        return True
    except Exception as e:
        logging.debug("wifi_dash _save %s: %s", path, e)
    return False

# ----------------------------
# plugin
# ----------------------------
class WiFiDash(plugins.Plugin):
    __author__ = "you"
    __version__ = "2.0"
    __name__ = "wifi_dash"
    __license__ = "MIT"
    __description__ = "Full wifi dashboard (read-only wpasec) and packaging for offline cracking"

    def __init__(self):
        # runtime
        self.options = {}
        self.config = {}
        self.wpasec_key = None

        # storage
        self.store_dir = "/root/.wifi_dash"
        self.history_path = None
        self.wordlist_dir = None
        self.ready_dir = None

        # data
        self.seen = {}      # current seen APs: keyed by bssid
        self.history = {}   # persisted history: keyed by bssid
        self.raw_agent_samples = []  # store last few agent payloads for debug

    # called when plugin loads
    def on_loaded(self):
        _ensure_dir(self.store_dir)
        self.history_path = os.path.join(self.store_dir, "history.json")
        self.wordlist_dir = os.path.join(self.store_dir, "wordlists")
        self.ready_dir = os.path.join(self.store_dir, "ready_for_crack")
        _ensure_dir(self.wordlist_dir)
        _ensure_dir(self.ready_dir)
        self.history = _load(self.history_path, {})
        # quick refresh of any existing wordlists
        self._refresh_wordlists()
        logging.info("wifi_dash loaded, history entries: %d", len(self.history))

    # called when config changes (also called soon after on_loaded)
    def on_config_changed(self, config):
        self.config = config or {}
        # plugin framework usually sets self.options separately; keep it defensive
        self.options = getattr(self, "options", {}) or {}
        self.wpasec_key = self._find_wpasec_api_key()
        logging.debug("wifi_dash config changed wpasec_key present=%s", bool(self.wpasec_key))

    # many pwnagotchi versions call different callbacks or provide ap lists in various forms.
    # We implement several handlers to ensure we receive the lists.
    def on_wifi_update(self, agent, access_points):
        # older/newer runtimes may send 'access_points' as a list
        # save raw snapshot for debug
        try:
            self._store_raw_agent(agent, "on_wifi_update")
        except Exception:
            pass
        self._parse_access_points(access_points)

    def on_unfiltered_ap_list(self, agent, ap_list):
        # some plugins use raw unfiltered list
        try:
            self._store_raw_agent(agent, "on_unfiltered_ap_list")
        except Exception:
            pass
        self._parse_access_points(ap_list)

    def on_handshake(self, agent, handshake):
        # keep raw for debug and to save reference for packaging
        # handshake structure differs; save minimal info
        try:
            self._store_raw_agent(agent, "on_handshake")
            # fingerprint handshake into history if it contains bssid/essid
            bssid = handshake.get("bssid") or handshake.get("ap") or handshake.get("mac")
            essid = handshake.get("essid") or handshake.get("ssid") or handshake.get("ap_name")
            if bssid:
                item = {
                    "bssid": bssid,
                    "ssid": _safe(essid),
                    "handshake_file": handshake.get("file") or handshake.get("pcap") or None,
                    "ts": _now()
                }
                self.history[bssid] = item
                _save(self.history_path, self.history)
        except Exception as e:
            logging.debug("wifi_dash on_handshake parse error: %s", e)

    # helper: robustly parse many shapes of AP lists
    def _parse_access_points(self, aps):
        if not aps:
            return
        try:
            # aps might be a dict with 'access_points' inside
            if isinstance(aps, dict):
                # try common fields
                candidates = []
                for k in ("access_points", "aps", "list", "scanned"):
                    if isinstance(aps.get(k), list):
                        candidates = aps.get(k)
                        break
                if not candidates:
                    # maybe dict keyed by bssid
                    for k, v in aps.items():
                        if isinstance(v, dict) and ":" in k:
                            candidates.append(v)
                aps = candidates or []
            # if still a dict-like mapping, convert
            if isinstance(aps, dict):
                aps = list(aps.values())

            # at this point we expect aps to be a list of dicts
            for ap in aps or []:
                if not isinstance(ap, dict):
                    continue
                # try to discover bssid and ssid fields from many possible names
                bssid = ap.get("bssid") or ap.get("mac") or ap.get("ap") or ap.get("address")
                ssid = ap.get("essid") or ap.get("ssid") or ap.get("name")
                rssi = ap.get("rssi") or ap.get("signal") or ap.get("strength") or ap.get("level")
                chan = ap.get("channel") or ap.get("chan")
                if not bssid:
                    # some entries use nested structure, try common nested keys
                    # skip entries without bssid
                    continue
                bssid = _safe(bssid).lower()
                row = {
                    "bssid": bssid,
                    "ssid": _safe(ssid),
                    "rssi": rssi,
                    "chan": chan,
                    "last_seen": _now()
                }
                self.seen[bssid] = row
                # keep a simple history snapshot
                if bssid not in self.history:
                    self.history[bssid] = {
                        "bssid": bssid,
                        "ssid": _safe(ssid),
                        "first_seen": _now(),
                        "last_seen": _now()
                    }
                else:
                    self.history[bssid]["last_seen"] = _now()

            # persist history occasionally
            if int(time.time()) % 17 == 0:
                _save(self.history_path, self.history)
        except Exception as e:
            logging.debug("wifi_dash _parse_access_points error: %s", e)

    # store a small sample of raw agent payloads so user can debug
    def _store_raw_agent(self, agent, tag):
        try:
            sample = {"tag": tag, "ts": _now(), "agent_keys": None, "raw": None}
            # store only keys to avoid huge payload
            if isinstance(agent, dict):
                sample["agent_keys"] = list(agent.keys())[:40]
            # save small json representation if safe
            try:
                sample["raw"] = json.dumps(agent, default=str)[:4000]
            except Exception:
                sample["raw"] = str(type(agent))
            self.raw_agent_samples.insert(0, sample)
            # keep only last 6
            self.raw_agent_samples = self.raw_agent_samples[:6]
        except Exception as e:
            logging.debug("wifi_dash store_raw_agent: %s", e)

    # find wpasec api key robustly
    def _find_wpasec_api_key(self):
        # 1) plugin options
        try:
            candidates = ("api_key", "wpasec_api_key", "wpasec_api_token", "apikey")
            for k in candidates:
                v = self.options.get(k) if isinstance(self.options, dict) else None
                if v:
                    logging.debug("wifi_dash found key in options %s", k)
                    return v
        except Exception:
            pass
        # 2) live config object from framework
        try:
            main = self.config.get("main", {}) if isinstance(self.config, dict) else {}
            plugins_cfg = main.get("plugins", {}) if isinstance(main, dict) else {}
            for plugin_name in ("wpa-sec", "wpa_sec", "wpasec"):
                section = plugins_cfg.get(plugin_name)
                if isinstance(section, dict):
                    for k in ("api_key", "apikey", "key"):
                        v = section.get(k)
                        if v:
                            logging.debug("wifi_dash found key in config main.plugins.%s.%s", plugin_name, k)
                            return v
        except Exception as e:
            logging.debug("wifi_dash _find_wpasec_api_key config check err: %s", e)
        # 3) fallback read /etc/pwnagotchi/config.toml if toml available
        try:
            cfg_file = "/etc/pwnagotchi/config.toml"
            if toml and os.path.exists(cfg_file):
                parsed = toml.load(open(cfg_file, "rb"))
                main = parsed.get("main", {}) if isinstance(parsed, dict) else {}
                plugins_cfg = main.get("plugins", {}) if isinstance(main, dict) else {}
                for plugin_name in ("wpa-sec", "wpa_sec", "wpasec"):
                    section = plugins_cfg.get(plugin_name)
                    if isinstance(section, dict):
                        for k in ("api_key", "apikey", "key"):
                            v = section.get(k)
                            if v:
                                logging.debug("wifi_dash found key in file main.plugins.%s.%s", plugin_name, k)
                                return v
        except Exception as e:
            logging.debug("wifi_dash _find_wpasec_api_key file check err: %s", e)
        return None

    # return wpasec cracked results (read-only). If requests not installed or key missing, returns []
    def _get_wpasec_results(self):
        if not self.wpasec_key or not requests:
            return []
        try:
            url = "https://wpa-sec.stanev.org/api"
            r = requests.get(url, headers={"API-Key": self.wpasec_key}, timeout=8)
            if r.status_code == 200:
                return r.json() if r.headers.get("content-type", "").startswith("application/json") else []
        except Exception as e:
            logging.debug("wifi_dash _get_wpasec_results err: %s", e)
        return []

    # wordlist helpers
    def _refresh_wordlists(self):
        try:
            _ensure_dir(self.wordlist_dir)
            files = [f for f in os.listdir(self.wordlist_dir) if os.path.isfile(os.path.join(self.wordlist_dir, f))]
            # accept .txt and .lst
            self.wordlists = sorted([f for f in files if f.lower().endswith((".txt", ".lst"))])
        except Exception as e:
            logging.debug("wifi_dash _refresh_wordlists: %s", e)
            self.wordlists = []

    # prepare a package for offline cracking
    # collects: selected handshake pcaps (from /root/handshakes or wherever user keeps them) and chosen wordlist
    # we cannot run the crack, we only prepare the archive for user to fetch
    def _prepare_package(self, bssid, chosen_wordlist):
        # locate handshake files in a few common places; this may vary by image
        candidate_dirs = [
            "/root/handshakes",
            "/root/hs",
            "/root/pcaps",
            "/root/captures",
            "/var/lib/pwnagotchi/handshakes",
            "/etc/pwnagotchi"
        ]
        matches = []
        # search for filenames containing bssid
        short_b = bssid.replace(":", "").lower()
        for d in candidate_dirs:
            try:
                if not os.path.isdir(d):
                    continue
                for fn in os.listdir(d):
                    low = fn.lower()
                    if short_b in low or bssid.replace(":", "").lower() in low:
                        matches.append(os.path.join(d, fn))
            except Exception:
                pass
        # if handshake filename stored in history, try that
        hs_file = None
        if bssid in self.history and isinstance(self.history[bssid], dict):
            hs_file = self.history[bssid].get("handshake_file")
            if hs_file and os.path.exists(hs_file):
                matches.append(hs_file)
        # ensure chosen wordlist exists
        wl_path = os.path.join(self.wordlist_dir, chosen_wordlist) if chosen_wordlist else None
        if wl_path and not os.path.exists(wl_path):
            wl_path = None

        if not matches and not wl_path:
            return None, "no handshakes or wordlist found for package"

        # produce a tar.gz named by bssid+timestamp
        name = f"{bssid.replace(':','')}_{int(time.time())}.tar.gz"
        out_path = os.path.join(self.ready_dir, name)
        try:
            with tarfile.open(out_path, "w:gz") as tar:
                for m in matches:
                    try:
                        tar.add(m, arcname=os.path.basename(m))
                    except Exception:
                        pass
                if wl_path:
                    try:
                        tar.add(wl_path, arcname=os.path.basename(wl_path))
                    except Exception:
                        pass
            return out_path, None
        except Exception as e:
            logging.debug("wifi_dash _prepare_package err: %s", e)
            return None, "failed creating package"

    # ----------------------------
    # web UI (on_webhook). full HTML returned
    # ----------------------------
    def on_webhook(self, path, request):
        # accept actions: wl_add, wl_del, reset_hist, upload_pwlist, del_pwlist, prepare_pkg
        action = request.args.get("action", default="") if hasattr(request, "args") else ""
        value = request.args.get("value", default="") if hasattr(request, "args") else ""
        # files if upload
        files = getattr(request, "files", None)

        # perform actions
        if action == "wl_add":
            v = value.strip()
            if v:
                wl = self.config.get("main", {}).get("whitelist", []) or []
                if v not in wl:
                    wl.append(v)
                    self._set_whitelist(wl)
        elif action == "wl_del":
            v = value.strip()
            wl = self.config.get("main", {}).get("whitelist", []) or []
            wl = [x for x in wl if x != v]
            self._set_whitelist(wl)
        elif action == "reset_hist":
            self.history = {}
            _save(self.history_path, self.history)
        elif action == "upload_pwlist":
            # file upload: framework exposes files mapping
            try:
                if files and "pwfile" in files:
                    f = files["pwfile"]
                    # f should have .filename and .save() method in the pwnagotchi web stack
                    out = os.path.join(self.wordlist_dir, f.filename)
                    f.save(out)
                    # refresh list
                    self._refresh_wordlists()
            except Exception as e:
                logging.debug("wifi_dash upload err: %s", e)
        elif action == "del_pwlist":
            try:
                p = os.path.join(self.wordlist_dir, value)
                if os.path.exists(p):
                    os.remove(p)
                self._refresh_wordlists()
            except Exception:
                pass
        elif action == "prepare_pkg":
            # value expected "bssid|wordlistname"
            try:
                parts = value.split("|", 1)
                bssid = parts[0]
                wl = parts[1] if len(parts) > 1 else None
                out, err = self._prepare_package(bssid, wl)
                if out:
                    # return a JSON response for package created
                    return json.dumps({"ok": True, "package": out})
                else:
                    return json.dumps({"ok": False, "err": err})
            except Exception as e:
                logging.debug("wifi_dash prepare_pkg err: %s", e)
                return json.dumps({"ok": False, "err": "unexpected error"})

        # update runtime lists
        self._refresh_wordlists()
        wpasec = self._get_wpasec_results()
        # build HTML
        html = self._render_ui(wpasec)
        # if export requested
        if request.args.get("export") == "json":
            return json.dumps(self.history), 200, {"Content-Type": "application/json"}
        return html

    # helper to write whitelist back in live config (framework should save when user hits "save" via webcfg)
    def _set_whitelist(self, wl):
        try:
            if "main" not in self.config:
                self.config["main"] = {}
            self.config["main"]["whitelist"] = wl
            return True
        except Exception as e:
            logging.debug("wifi_dash _set_whitelist: %s", e)
            return False

    # UI builder
    def _render_ui(self, wpasec):
        # safer copies
        seen = dict(self.seen)
        history = dict(self.history)
        wl = self.config.get("main", {}).get("whitelist", []) or []
        # small style like iOS settings
        style = """
        <style>
        body{font-family:-apple-system,Helvetica,Arial;margin:0;background:#f2f2f7;color:#111}
        .header{padding:14px 16px;background:#fff;border-bottom:1px solid #e6e6e6;display:flex;justify-content:space-between;align-items:center}
        .title{font-size:18px;font-weight:600}
        .container{padding:12px}
        .panel{background:#fff;border-radius:12px;padding:8px;margin-bottom:12px;box-shadow:0 1px 2px rgba(0,0,0,.06)}
        .row{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border-bottom:1px solid #f0f0f0}
        .row:last-child{border-bottom:none}
        .ssid{font-weight:600}
        .meta{color:#666;font-size:12px;margin-top:4px}
        .btn{display:inline-block;padding:6px 10px;border-radius:8px;background:#007aff;color:#fff;text-decoration:none;}
        .small{font-size:12px;color:#888}
        .debug{font-family:monospace;font-size:12px;color:#444;white-space:pre-wrap;max-height:260px;overflow:auto;background:#fff;padding:8px;border-radius:8px;border:1px solid #eee}
        .flex{display:flex;gap:8px;align-items:center}
        form{display:inline}
        </style>
        """

        # live networks
        nets_html = ""
        if seen:
            # sort by rssi desc where available
            def sortkey(x):
                r = x[1].get("rssi")
                try:
                    return int(r) if r is not None else -999
                except:
                    return -999
            for bssid, ap in sorted(seen.items(), key=sortkey, reverse=True):
                ssid = ap.get("ssid") or "(hidden)"
                rssi = ap.get("rssi") or ""
                chan = ap.get("chan") or ""
                bars = _bars(_rssi_bucket(rssi))
                add_btn = f"<a class='btn' href='?action=wl_add&value={bssid}'>Whitelist</a>"
                nets_html += f"<div class='row'><div><div class='ssid'>{ssid}</div><div class='meta'>{bssid} • ch {chan} • {rssi} dBm • {bars}</div></div><div class='flex'>{add_btn}</div></div>"
        else:
            nets_html = "<div class='row'><div class='small'>no live networks detected yet</div></div>"

        # whitelist html
        wl_html = ""
        if wl:
            for e in wl:
                wl_html += f"<div class='row'><div>{e}</div><div><a class='btn' href='?action=wl_del&value={e}'>Remove</a></div></div>"
        else:
            wl_html = "<div class='row'><div class='small'>empty</div></div>"

        # wpasec cracked results
        cracks_html = ""
        if wpasec:
            # many results may be dicts with keys essid,bssid,password - show those
            for r in wpasec:
                essid = r.get("essid") or r.get("ssid") or r.get("name") or "?"
                bssid = r.get("bssid") or r.get("ap") or "?"
                pwd = r.get("password") or r.get("pass") or "?"
                cracks_html += f"<div class='row'><div><div class='ssid'>{essid}</div><div class='meta'>{bssid} • {pwd}</div></div></div>"
        else:
            cracks_html = "<div class='row'><div class='small'>no wpasec results or api not configured</div></div>"

        # history html
        hist_html = ""
        if history:
            # sort by last_seen or first_seen
            def hkey(x):
                v = x[1].get("last_seen") or x[1].get("first_seen") or 0
                return int(v)
            for bssid, ap in sorted(history.items(), key=hkey, reverse=True):
                ssid = ap.get("ssid") or "(unknown)"
                last = _ts(ap.get("last_seen") or ap.get("last") or ap.get("first_seen") or 0)
                hist_html += f"<div class='row'><div><div class='ssid'>{ssid}</div><div class='meta'>{bssid} • last seen {last}</div></div></div>"
        else:
            hist_html = "<div class='row'><div class='small'>history empty</div></div>"

        # wordlists html (upload form)
        self._refresh_wordlists()
        wlst_html = ""
        if getattr(self, "wordlists", None):
            for fn in self.wordlists:
                wlst_html += f"<div class='row'><div>{fn}</div><div><a class='btn' href='?action=del_pwlist&value={fn}'>Delete</a></div></div>"
        else:
            wlst_html = "<div class='row'><div class='small'>no uploaded wordlists</div></div>"
        upload_form = """
            <div class='row'><form action='?action=upload_pwlist' method='post' enctype='multipart/form-data'>
            <input type='file' name='pwfile'>
            <button class='btn' type='submit'>Upload</button></form></div>
        """

        # ready packages list
        ready_html = ""
        try:
            pkgs = sorted([f for f in os.listdir(self.ready_dir) if os.path.isfile(os.path.join(self.ready_dir,f))], reverse=True)
            if pkgs:
                for p in pkgs:
                    ready_html += f"<div class='row'><div>{p}</div><div><a class='btn' href='/plugins/wifi_dash?download={p}'>Download</a></div></div>"
            else:
                ready_html = "<div class='row'><div class='small'>no ready packages</div></div>"
        except Exception:
            ready_html = "<div class='row'><div class='small'>no ready packages</div></div>"

        # raw agent debug
        debug_html = "<div class='debug'>"
        for s in self.raw_agent_samples:
            debug_html += f"[{_ts(s['ts'])}] {s['tag']} keys:{s.get('agent_keys')}\\n{_safe(s.get('raw'))}\\n----\\n"
        debug_html += "</div>"

        # final html: top header with controls to export json and reset
        html = f"""
        <html><head><meta charset='utf-8'><title>WiFi Dash</title>{style}</head><body>
        <div class='header'><div class='title'>Wi-Fi Dash</div>
            <div>
              <a class='btn' href='?export=json'>Export JSON</a>
              <a class='btn' href='?action=reset_hist'>Reset History</a>
            </div>
        </div>
        <div class='container'>
            <div class='panel'><div style='padding:10px;font-weight:600'>Live networks</div>{nets_html}</div>
            <div class='panel'><div style='padding:10px;font-weight:600'>Whitelist</div>{wl_html}</div>
            <div class='panel'><div style='padding:10px;font-weight:600'>WPA-Sec cracked results</div>{cracks_html}</div>
            <div class='panel'><div style='padding:10px;font-weight:600'>History</div>{hist_html}</div>
            <div class='panel'><div style='padding:10px;font-weight:600'>Password lists</div>{wlst_html}{upload_form}</div>
            <div class='panel'><div style='padding:10px;font-weight:600'>Ready packages (packaged handshake + wordlist)</div>{ready_html}</div>
            <div class='panel'><div style='padding:10px;font-weight:600'>Raw agent/debug (helpful if lists are empty)</div>{debug_html}</div>
        </div>
        </body></html>
        """
        return html

    # allow downloading prepared package via query param ?download=filename
    def on_web_request(self, request):
        # some web frameworks call on_web_request instead of using on_webhook return tuples
        # we implement this to allow file download if the web server calls this hook
        download = request.args.get("download") if hasattr(request, "args") else None
        if download:
            path = os.path.join(self.ready_dir, download)
            if os.path.exists(path):
                # return a tuple expected by framework: (content, code, headers) or special file response
                with open(path, "rb") as f:
                    data = f.read()
                return data, 200, {"Content-Type": "application/gzip", "Content-Disposition": f"attachment; filename={download}"}
        # fallback to default
        return None

# end of plugin
