# ============================================================
# DigiCure  -  ESP32-S3 (DigiComp N16R8)  -  main.py
# 240x280 ST7789 + CST816T touch, MicroPython
#
# * Framebuffer size adapts to free RAM (full screen if PSRAM is
#   enabled, otherwise horizontal strips). It never fails to boot
#   with "can't allocate".
# * Vault is AES-256-CBC + HMAC-SHA256, key derived from your PIN.
#   The PIN itself is never stored. First boot asks you to choose one.
# * Wrong PIN counter is stored in flash; lockout grows with fails.
# * Add via Wi-Fi (own access point, random password, tap to save).
# * USB keyboard typing (needs the usb-device-keyboard package).
# ============================================================

from machine import Pin, SPI, I2C
import framebuf
import time
import math
import gc
import os
import json
import sys
import select

try:
    import hashlib
except ImportError:
    import uhashlib as hashlib

try:
    import cryptolib as _cl
except ImportError:
    import ucryptolib as _cl

gc.collect()
HAS_PSRAM = gc.mem_free() > 1000000

# ============================================================
# SETTINGS
# ============================================================

PIN_LEN = 4            # changing this later means a new vault
KDF_ROUNDS = 3000
VAULT_FILE = "/vault.enc"
FAIL_FILE = "/fails.txt"
AP_TIMEOUT_S = 180
ROWS = 4               # entries per page

W = 240
H = 280
Y_OFF = 20

# ============================================================
# FRAMEBUFFER (adaptive)
# ============================================================

buf = None
fb = None
STRIP_H = 20


def alloc_fb():
    global buf, fb, STRIP_H
    for h in (280, 140, 70, 40, 20):
        gc.collect()
        try:
            buf = bytearray(W * h * 2)
            fb = framebuf.FrameBuffer(buf, W, h, framebuf.RGB565)
            STRIP_H = h
            return
        except MemoryError:
            buf = None
            fb = None
    raise MemoryError("no RAM for display buffer")


alloc_fb()
gc.collect()

# ============================================================
# PINS
# ============================================================

LCD_SCK = 6
LCD_MOSI = 7
LCD_CS = 5
LCD_DC = 8
LCD_RST = 15
LCD_BL = 4

TP_SDA = 11
TP_SCL = 12
TP_RST = 9
TP_IRQ = 10
TP_ADDR = 0x15

# ============================================================
# COLOURS
# ============================================================


def rgb(r, g, b):
    c = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
    return ((c >> 8) | ((c & 0xFF) << 8)) & 0xFFFF


CREAM = rgb(255, 244, 225)
INK = rgb(70, 28, 78)
KEY_BG = rgb(255, 236, 208)
SUN = rgb(255, 226, 140)
HALO1 = rgb(255, 170, 90)
HALO2 = rgb(255, 196, 110)
HILL = rgb(92, 36, 96)
GROUND = rgb(52, 22, 66)
RED = rgb(255, 80, 90)
STAR = rgb(255, 240, 220)

SKY_STOPS = (
    (0.00, (38, 24, 84)),
    (0.35, (120, 48, 120)),
    (0.60, (240, 100, 100)),
    (0.82, (255, 160, 70)),
    (1.00, (255, 214, 120)),
)


def sky_color(y):
    t = y / (H - 1)
    for i in range(len(SKY_STOPS) - 1):
        t0, c0 = SKY_STOPS[i]
        t1, c1 = SKY_STOPS[i + 1]
        if t <= t1:
            k = (t - t0) / (t1 - t0)
            return rgb(
                int(c0[0] + (c1[0] - c0[0]) * k),
                int(c0[1] + (c1[1] - c0[1]) * k),
                int(c0[2] + (c1[2] - c0[2]) * k),
            )
    return rgb(255, 214, 120)


SKY = [sky_color(y) for y in range(H)]

# ============================================================
# SPI / LCD
# ============================================================

spi = SPI(
    1,
    baudrate=80_000_000,
    polarity=0,
    phase=0,
    sck=Pin(LCD_SCK),
    mosi=Pin(LCD_MOSI),
)

cs = Pin(LCD_CS, Pin.OUT, value=1)
dc = Pin(LCD_DC, Pin.OUT, value=0)
rst = Pin(LCD_RST, Pin.OUT, value=1)
bl = Pin(LCD_BL, Pin.OUT, value=0)


def cmd(c, data=None):
    cs(0)
    dc(0)
    spi.write(bytes([c]))
    if data:
        dc(1)
        spi.write(data)
    cs(1)


def lcd_init():
    rst(1)
    time.sleep_ms(20)
    rst(0)
    time.sleep_ms(20)
    rst(1)
    time.sleep_ms(120)

    cmd(0x01)
    time.sleep_ms(150)
    cmd(0x11)
    time.sleep_ms(120)

    cmd(0x3A, b'\x05')
    cmd(0x36, b'\x00')
    cmd(0xB2, b'\x0C\x0C\x00\x33\x33')
    cmd(0xB7, b'\x35')
    cmd(0xBB, b'\x1F')
    cmd(0xC0, b'\x2C')
    cmd(0xC2, b'\x01')
    cmd(0xC3, b'\x12')
    cmd(0xC4, b'\x20')
    cmd(0xC6, b'\x0F')
    cmd(0xD0, b'\xA4\xA1')
    cmd(0xE0, b'\xD0\x08\x11\x08\x0C\x15\x39\x33\x50\x36\x13\x14\x29\x2D')
    cmd(0xE1, b'\xD0\x08\x10\x08\x06\x06\x39\x44\x51\x0B\x16\x14\x2F\x31')
    cmd(0x21)
    cmd(0x13)
    cmd(0x29)
    time.sleep_ms(20)
    bl(1)


# ============================================================
# STRIP ENGINE
# ============================================================

_current_y = 0


def begin_strip(y):
    global _current_y
    _current_y = y
    fb.fill(0)


def end_strip():
    y0 = _current_y
    y1 = y0 + STRIP_H - 1
    cmd(0x2A, bytes([0, 0, (W - 1) >> 8, (W - 1) & 0xFF]))
    p0 = y0 + Y_OFF
    p1 = y1 + Y_OFF
    cmd(0x2B, bytes([p0 >> 8, p0 & 0xFF, p1 >> 8, p1 & 0xFF]))
    cs(0)
    dc(0)
    spi.write(b'\x2C')
    dc(1)
    spi.write(buf)
    cs(1)


_btns = []


def render_screen(draw_function):
    global _btns
    _btns = []
    for y in range(0, H, STRIP_H):
        begin_strip(y)
        draw_function()
        end_strip()


# ============================================================
# DRAWING PRIMITIVES
# ============================================================


def visible(y, h=1):
    return y + h > _current_y and y < _current_y + STRIP_H


def line_h(x, y, w, c):
    if visible(y):
        fb.hline(x, y - _current_y, w, c)


def rect(x, y, w, h, c):
    if not visible(y, h):
        return
    top = max(y, _current_y)
    bottom = min(y + h, _current_y + STRIP_H)
    if bottom <= top:
        return
    fb.fill_rect(x, top - _current_y, w, bottom - top, c)


def pixel(x, y, c):
    if visible(y):
        fb.pixel(x, y - _current_y, c)


def fill_circle(cx, cy, r, c):
    start = max(cy - r, _current_y)
    end = min(cy + r, _current_y + STRIP_H - 1)
    rr = r * r
    for y in range(start, end + 1):
        dy = y - cy
        dx = int(math.sqrt(rr - dy * dy))
        fb.hline(cx - dx, y - _current_y, 2 * dx + 1, c)


def rrect(x, y, w, h, r, c):
    rect(x + r, y, w - 2 * r, h, c)
    rect(x, y + r, w, h - 2 * r, c)
    fill_circle(x + r, y + r, r, c)
    fill_circle(x + w - r - 1, y + r, r, c)
    fill_circle(x + r, y + h - r - 1, r, c)
    fill_circle(x + w - r - 1, y + h - r - 1, r, c)


_ch = bytearray(8)
_cb = framebuf.FrameBuffer(_ch, 8, 8, framebuf.MONO_HLSB)


def text(s, x, y, c, sc=1):
    if sc == 1:
        if visible(y, 8):
            fb.text(s, x, y - _current_y, c)
        return
    if not visible(y, 8 * sc):
        return
    for i in range(len(s)):
        _cb.fill(0)
        _cb.text(s[i], 0, 0, 1)
        ox = x + i * 8 * sc
        for r in range(8):
            row = _ch[r]
            if row:
                yy = y + r * sc
                if not visible(yy, sc):
                    continue
                for b in range(8):
                    if row & (0x80 >> b):
                        rect(ox + b * sc, yy, sc, sc, c)


def textc(s, y, c, sc=1, cx=120):
    text(s, cx - len(s) * 4 * sc, y, c, sc)


def clip(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "~"


def draw_sky_strip():
    y0 = _current_y
    for y in range(y0, min(y0 + STRIP_H, H)):
        fb.hline(0, y - y0, W, SKY[y])


def btn(bid, x, y, w, h, label, bg=None, fg=None, sc=1, r=10):
    if _current_y == 0:
        _btns.append((bid, x, y, w, h))
    rrect(x, y, w, h, r, KEY_BG if bg is None else bg)
    textc(label, y + (h - 8 * sc) // 2, INK if fg is None else fg,
          sc, x + w // 2)


# ============================================================
# TOUCH
# ============================================================

i2c = I2C(0, sda=Pin(TP_SDA), scl=Pin(TP_SCL), freq=400_000)
tp_rst = Pin(TP_RST, Pin.OUT, value=1)


def touch_init():
    tp_rst(0)
    time.sleep_ms(10)
    tp_rst(1)
    time.sleep_ms(60)


def touch():
    try:
        d = i2c.readfrom_mem(TP_ADDR, 0x01, 6)
    except OSError:
        return None
    if d[1] == 0:
        return None
    x = ((d[2] & 0x0F) << 8) | d[3]
    y = ((d[4] & 0x0F) << 8) | d[5]
    return x, y


def hit(pt, x, y, w, h):
    return pt is not None and x <= pt[0] < x + w and y <= pt[1] < y + h


# ============================================================
# CRYPTO + VAULT
# ============================================================

MAGIC = b"DC1"
sha256 = hashlib.sha256

entries = []
_ke = None
_km = None
_salt = None


def derive(pin, salt):
    p = pin.encode()
    k = sha256(salt + p).digest()
    for _ in range(KDF_ROUNDS):
        k = sha256(k + salt + p).digest()
    return sha256(k + b"E").digest(), sha256(k + b"M").digest()


def hmac256(key, msg):
    k = key + bytes(64 - len(key))
    ipad = bytes([x ^ 0x36 for x in k])
    opad = bytes([x ^ 0x5C for x in k])
    inner = sha256(ipad + msg).digest()
    return sha256(opad + inner).digest()


def ct_eq(a, b):
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


def vault_exists():
    try:
        os.stat(VAULT_FILE)
        return True
    except OSError:
        return False


def recover_vault():
    if not vault_exists():
        try:
            os.stat(VAULT_FILE + ".tmp")
            os.rename(VAULT_FILE + ".tmp", VAULT_FILE)
        except OSError:
            pass


def save_vault():
    iv = os.urandom(16)
    data = json.dumps(entries).encode()
    pad = 16 - len(data) % 16
    data = data + bytes([pad]) * pad
    ct = _cl.aes(_ke, 2, iv).encrypt(data)
    body = MAGIC + _salt + iv + ct
    blob = body + hmac256(_km, body)
    tmp = VAULT_FILE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
    try:
        os.remove(VAULT_FILE)
    except OSError:
        pass
    os.rename(tmp, VAULT_FILE)


def load_vault(pin):
    global entries, _ke, _km, _salt
    with open(VAULT_FILE, "rb") as f:
        blob = f.read()
    if blob[:3] != MAGIC or len(blob) < 3 + 16 + 16 + 16 + 32:
        return False
    salt = blob[3:19]
    iv = blob[19:35]
    ct = blob[35:-32]
    mac = blob[-32:]
    if len(ct) % 16:
        return False
    ke, km = derive(pin, salt)
    if not ct_eq(hmac256(km, blob[:-32]), mac):
        return False
    pt = _cl.aes(ke, 2, iv).decrypt(ct)
    pad = pt[-1]
    entries = json.loads(pt[:-pad])
    _ke, _km, _salt = ke, km, salt
    return True


def set_new_pin(pin):
    global _ke, _km, _salt
    _salt = os.urandom(16)
    _ke, _km = derive(pin, _salt)
    save_vault()


def wipe_session():
    global entries, _ke, _km
    entries = []
    _ke = None
    _km = None
    gc.collect()


def get_fails():
    try:
        with open(FAIL_FILE) as f:
            return int(f.read().strip() or "0")
    except (OSError, ValueError):
        return 0


def set_fails(n):
    try:
        with open(FAIL_FILE, "w") as f:
            f.write(str(n))
    except OSError:
        pass


def penalty(n):
    return 0 if n < 3 else min(30 * (n - 2), 600)


# ============================================================
# USB KEYBOARD (HID)
# ============================================================

_kbd = None
_SHIFTED = "!@#$%^&*()"
_PLAIN = {' ': 44, '-': 45, '=': 46, '[': 47, ']': 48, '\\': 49,
          ';': 51, "'": 52, '`': 53, ',': 54, '.': 55, '/': 56}
_SHIFT = {'_': 45, '+': 46, '{': 47, '}': 48, '|': 49, ':': 51,
          '"': 52, '~': 53, '<': 54, '>': 55, '?': 56}


def hid_code(ch):
    o = ord(ch)
    if 97 <= o <= 122:
        return o - 93, False
    if 65 <= o <= 90:
        return o - 61, True
    if ch == '0':
        return 39, False
    if '1' <= ch <= '9':
        return o - 19, False
    i = _SHIFTED.find(ch)
    if i >= 0:
        return 30 + i, True
    if ch in _PLAIN:
        return _PLAIN[ch], False
    if ch in _SHIFT:
        return _SHIFT[ch], True
    return None, False


def hid_init():
    global _kbd
    if _kbd is not None:
        return True
    try:
        import usb.device
        from usb.device.keyboard import KeyboardInterface
        k = KeyboardInterface()
        usb.device.get().init(k, builtin_driver=True)
        _kbd = k
        return True
    except Exception as e:
        print("HID unavailable:", e)
        return False


def type_text(s):
    k = _kbd
    t = 30
    while not k.is_open() and t > 0:
        time.sleep_ms(100)
        t -= 1
    if not k.is_open():
        return False
    for ch in s:
        code, shift = hid_code(ch)
        if code is None:
            continue
        keys = [0xE1, code] if shift else [code]
        k.send_keys(keys)
        time.sleep_ms(15)
        k.send_keys([], keys)
        time.sleep_ms(15)
    return True


# ============================================================
# WI-FI ADD (own access point, on demand)
# ============================================================

_srv = None
_ap = None
_ssid = ""
_apw = ""
_wifi_deadline = 0
_wleft = 0
_pending = None

_PAGE = (
    "<!doctype html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>DigiCure</title><style>body{font-family:sans-serif;"
    "background:#2a1846;color:#fff4e1;padding:20px}input{width:100%;"
    "padding:12px;margin:6px 0 14px;border-radius:8px;border:0;"
    "font-size:16px;box-sizing:border-box}button{width:100%;padding:14px;"
    "border:0;border-radius:8px;background:#ffaa5a;font-size:18px}"
    "</style></head><body><h2>DigiCure</h2>"
    "<form method='POST' action='/'>"
    "Name<input name='n' maxlength='24' required>"
    "Username<input name='u' maxlength='48'>"
    "Password<input name='p' type='password' maxlength='64' required>"
    "<button>Send to device</button></form></body></html>"
)

_DONE = (
    "<!doctype html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "</head><body style='font-family:sans-serif;padding:20px'>"
    "<h3>Received</h3><p>Now tap SAVE on the DigiCure screen.</p>"
    "</body></html>"
)


def rand_pw(n):
    chars = "abcdefghjkmnpqrstuvwxyz23456789"
    r = os.urandom(n)
    return "".join([chars[b % len(chars)] for b in r])


def wifi_start():
    global _srv, _ap, _ssid, _apw, _wifi_deadline, _wleft
    import network
    import socket
    gc.collect()
    ap = network.WLAN(network.AP_IF)
    ap.active(True)
    mac = ap.config("mac")
    _ssid = "DigiCure-%02X%02X" % (mac[4], mac[5])
    _apw = rand_pw(10)
    ap.config(essid=_ssid, password=_apw, authmode=network.AUTH_WPA2_PSK)
    _ap = ap
    s = socket.socket()
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    s.bind(("0.0.0.0", 80))
    s.listen(1)
    s.setblocking(False)
    _srv = s
    _wifi_deadline = time.ticks_add(time.ticks_ms(), AP_TIMEOUT_S * 1000)
    _wleft = AP_TIMEOUT_S


def wifi_stop():
    global _srv, _ap
    try:
        if _srv:
            _srv.close()
    except Exception:
        pass
    _srv = None
    try:
        if _ap:
            _ap.active(False)
    except Exception:
        pass
    _ap = None
    gc.collect()


def _read_req(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        c = conn.recv(512)
        if not c:
            break
        data += c
        if len(data) > 4096:
            break
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    first = lines[0] if lines else b""
    cl = 0
    for ln in lines[1:]:
        if ln.lower().startswith(b"content-length:"):
            try:
                cl = int(ln.split(b":")[1])
            except ValueError:
                cl = 0
    while len(body) < cl and len(body) < 2048:
        c = conn.recv(512)
        if not c:
            break
        body += c
    return first, body


def _urldecode(b):
    b = b.replace(b"+", b" ")
    out = bytearray()
    i = 0
    n = len(b)
    while i < n:
        if b[i] == 37 and i + 2 < n:
            try:
                out.append(int(b[i + 1:i + 3].decode(), 16))
                i += 3
                continue
            except ValueError:
                pass
        out.append(b[i])
        i += 1
    try:
        return bytes(out).decode("utf-8")
    except UnicodeError:
        return ""


def _parse_form(body):
    d = {}
    for part in body.split(b"&"):
        if b"=" in part:
            k, v = part.split(b"=", 1)
            d[k.decode()] = _urldecode(v)
    return d


def _send(conn, html):
    conn.send(b"HTTP/1.0 200 OK\r\nContent-Type: text/html; "
              b"charset=utf-8\r\nConnection: close\r\n\r\n")
    conn.send(html.encode())


def wifi_poll():
    try:
        conn, _ = _srv.accept()
    except OSError:
        return None
    result = None
    try:
        conn.settimeout(3)
        first, body = _read_req(conn)
        if first.startswith(b"POST"):
            f = _parse_form(body)
            n = f.get("n", "").strip()[:24]
            u = f.get("u", "").strip()[:48]
            p = f.get("p", "")[:64]
            if n and p:
                result = {"n": n, "u": u, "p": p, "f": 0}
                _send(conn, _DONE)
            else:
                _send(conn, _PAGE)
        else:
            _send(conn, _PAGE)
    except Exception as e:
        print("wifi req error:", e)
    try:
        conn.close()
    except Exception:
        pass
    return result


# ============================================================
# STATE
# ============================================================

S = "lock"
D = True


def go(s):
    global S, D
    S = s
    D = True


def redraw():
    global D
    render_screen(DRAW[S])
    D = False


# ---------------- USB serial link (used by the website) ----------------
# Lines look like  DC{"c":"list"}  (host -> device) and
# DC{"r":"list",...}  (device -> host). The PIN is never sent over USB.
_poll = select.poll()
_poll.register(sys.stdin, select.POLLIN)
_rx = ""
_link_add = False
_link_del = -1
_BUSY = ("wifi", "review", "confdel", "pin")


def link_send(d):
    print("DC" + json.dumps(d))


def link_cmd(m):
    global _pending, _link_add, _link_del
    c = m.get("c")
    if c == "hello":
        link_send({"r": "hello", "locked": _ke is None, "n": len(entries)})
    elif _ke is None:
        link_send({"r": c, "err": "locked"})
    elif c == "list":
        link_send({"r": "list", "items": [
            {"i": i, "n": e["n"], "u": e["u"], "f": e.get("f", 0)}
            for i, e in enumerate(entries)]})
    elif S in _BUSY:
        link_send({"r": c, "err": "busy"})
    elif c == "add":
        n = str(m.get("n", "")).strip()[:24]
        p = str(m.get("p", ""))[:64]
        if not n or not p:
            link_send({"r": "add", "err": "bad"})
            return
        _pending = {"n": n, "u": str(m.get("u", "")).strip()[:48],
                    "p": p, "f": 0}
        _link_add = True
        go("review")
    elif c == "del":
        i = m.get("i", -1)
        if isinstance(i, int) and 0 <= i < len(entries):
            _link_del = i
            go("confdel")
        else:
            link_send({"r": "del", "err": "bad"})


def link_poll():
    global _rx
    while _poll.poll(0):
        ch = sys.stdin.read(1)
        if not ch:
            break
        if ch == "\n":
            line = _rx.strip()
            _rx = ""
            if line.startswith("DC{"):
                try:
                    link_cmd(json.loads(line[2:]))
                except Exception as e:
                    print("link error:", e)
        elif len(_rx) < 1800:
            _rx += ch


# ============================================================
# SCREENS
# ============================================================

# ---------------- messages ----------------
_msg = ("", "", "")


def draw_msg_strip():
    draw_sky_strip()
    textc(_msg[0], 100, CREAM, 2)
    textc(_msg[1], 140, CREAM, 1)
    textc(_msg[2], 158, CREAM, 1)


def show_msg(a, b="", c=""):
    global _msg
    _msg = (a, b, c)
    render_screen(draw_msg_strip)


# ---------------- lock ----------------
STARS = ((20, 18), (58, 44), (96, 12), (150, 30), (190, 14), (220, 50),
         (30, 80), (205, 90), (75, 100), (170, 70), (120, 8), (12, 52))
HORIZON = 205
RISE_FRAMES = 70
_lock_frame = 0
_lkey = None


def draw_lock_strip():
    frame = _lock_frame
    t = min(frame / RISE_FRAMES, 1.0)
    p = 1 - (1 - t) ** 3
    draw_sky_strip()
    if p < 0.7:
        for sx, sy in STARS:
            pixel(sx, sy, STAR)
    cy = HORIZON + 34 - int(p * 80)
    pulse = int(3 * math.sin(frame / 8))
    fill_circle(120, cy, 56 + pulse, HALO1)
    fill_circle(120, cy, 46 + pulse, HALO2)
    fill_circle(120, cy, 34, SUN)
    fill_circle(28, 285, 95, HILL)
    fill_circle(222, 290, 88, HILL)
    rect(0, HORIZON + 3, W, H - HORIZON - 3, GROUND)
    textc("DigiCure", 26, CREAM, 3)
    textc("Your keys, at first light", 58, CREAM, 1)
    if t >= 1.0 and (frame // 18) % 2 == 0:
        textc("Tap to unlock", 240, CREAM, 1)


def go_lock():
    global _lock_frame, _lkey
    wipe_session()
    _lock_frame = 0
    _lkey = None
    go("lock")


# ---------------- PIN ----------------
KEY_W = 64
KEY_H = 40
LABELS = ("1", "2", "3", "4", "5", "6", "7", "8", "9", "DEL", "0", "ESC")
PIN_TITLE = {
    "unlock": "Enter PIN",
    "set1": "Choose PIN",
    "set2": "Repeat PIN",
    "new1": "New PIN",
    "new2": "Repeat PIN",
}
_pin_digits = ""
_pin_dx = 0
_pin_bad = False
_pin_mode = "unlock"
_pin_first = ""
_boot_pen_done = False


def draw_pin_strip():
    draw_sky_strip()
    if _pin_bad:
        textc("Wrong PIN", 14, RED, 2)
    else:
        textc(PIN_TITLE[_pin_mode], 14, CREAM, 2)
    sp = 32 if PIN_LEN <= 4 else 24
    for i in range(PIN_LEN):
        cx = 120 + int((i - (PIN_LEN - 1) / 2) * sp) + _pin_dx
        cy = 58
        if i < len(_pin_digits):
            fill_circle(cx, cy, 9, RED if _pin_bad else CREAM)
        else:
            fill_circle(cx, cy, 9, CREAM)
            fill_circle(cx, cy, 6, SKY[cy])
    for i, label in enumerate(LABELS):
        x = 16 + (i % 3) * (KEY_W + 8)
        y = 84 + (i // 3) * (KEY_H + 6)
        btn(label, x, y, KEY_W, KEY_H, label, sc=2)


def wrong_pin():
    global _pin_dx, _pin_bad
    _pin_bad = True
    for dx in (-10, 10, -8, 8, -5, 5, -2, 2, 0):
        _pin_dx = dx
        render_screen(draw_pin_strip)
        time.sleep_ms(30)
    time.sleep_ms(250)
    _pin_dx = 0
    _pin_bad = False


def lockout_wait(secs):
    end = time.ticks_add(time.ticks_ms(), secs * 1000)
    last = -1
    while True:
        left = time.ticks_diff(end, time.ticks_ms())
        if left <= 0:
            break
        s = (left + 999) // 1000
        if s != last:
            last = s
            show_msg("Too many tries", "Wait %d s" % s)
        time.sleep_ms(100)


def open_pin():
    global _pin_digits, _pin_bad, _pin_dx, _pin_mode, _boot_pen_done
    _pin_digits = ""
    _pin_bad = False
    _pin_dx = 0
    if not vault_exists():
        _pin_mode = "set1"
    else:
        _pin_mode = "unlock"
        if not _boot_pen_done:
            _boot_pen_done = True
            p = penalty(get_fails())
            if p:
                lockout_wait(p)
    go("pin")


def pin_finish():
    global _pin_digits, _pin_mode, _pin_first
    pin = _pin_digits
    m = _pin_mode
    if m == "unlock":
        ok = False
        try:
            ok = load_vault(pin)
        except Exception as e:
            print("load error:", e)
        if ok:
            set_fails(0)
            _pin_digits = ""
            go("home")
        else:
            n = get_fails() + 1
            set_fails(n)
            wrong_pin()
            _pin_digits = ""
            p = penalty(n)
            if p:
                lockout_wait(p)
            go("pin")
        return
    if m in ("set1", "new1"):
        _pin_first = pin
        _pin_mode = "set2" if m == "set1" else "new2"
        _pin_digits = ""
        go("pin")
        return
    # second entry
    _pin_digits = ""
    if pin == _pin_first:
        if m == "set2":
            wipe_session()
            set_new_pin(pin)
            set_fails(0)
            show_msg("PIN saved", "Vault created")
            time.sleep_ms(1000)
            go("home")
        else:
            set_new_pin(pin)
            show_msg("PIN changed")
            time.sleep_ms(1000)
            go("settings")
    else:
        show_msg("PINs differ", "Try again")
        time.sleep_ms(1200)
        _pin_mode = "set1" if m == "set2" else "new1"
        go("pin")


def pin_key(label):
    global _pin_digits
    if label == "ESC":
        if _pin_mode.startswith("new"):
            go("settings")
        else:
            go_lock()
        return
    if label == "DEL":
        _pin_digits = _pin_digits[:-1]
        redraw()
        return
    if len(_pin_digits) < PIN_LEN:
        _pin_digits += label
        redraw()
    if len(_pin_digits) == PIN_LEN:
        time.sleep_ms(120)
        pin_finish()


# ---------------- home ----------------
TILE_W = 104
TILE_H = 92
TILES = (("Passwords", 12, 64), ("Add", 124, 64),
         ("Favorites", 12, 168), ("Settings", 124, 168))


def _make_star():
    spans = []
    seg = 2 * math.pi / 5
    for yy in range(-17, 15):
        xs = []
        for xx in range(-17, 18):
            rr = math.sqrt(xx * xx + yy * yy)
            if rr >= 17:
                continue
            a = math.atan2(yy, xx)
            th = (a + math.pi / 2 + 2 * math.pi) % seg
            t = th if th <= seg / 2 else seg - th
            limit = 17 + (6 - 17) * t / (seg / 2)
            if rr <= limit:
                xs.append(xx)
        if xs:
            spans.append((yy, min(xs), max(xs) - min(xs) + 1))
    return spans


STAR_SPANS = _make_star()


def icon(name, cx, cy):
    if name == "Passwords":
        fill_circle(cx, cy - 6, 10, INK)
        fill_circle(cx, cy - 6, 5, KEY_BG)
        rrect(cx - 13, cy - 3, 26, 22, 4, INK)
        fill_circle(cx, cy + 6, 3, KEY_BG)
    elif name == "Add":
        rect(cx - 3, cy - 14, 6, 30, INK)
        rect(cx - 15, cy - 2, 30, 6, INK)
    elif name == "Favorites":
        for yy, x0, w in STAR_SPANS:
            line_h(cx + x0, cy + 2 + yy, w, INK)
    else:
        for i, kx in enumerate((-6, 6, -2)):
            yy = cy - 12 + i * 12
            rect(cx - 15, yy, 30, 3, INK)
            fill_circle(cx + kx, yy + 1, 5, INK)


def draw_home_strip():
    draw_sky_strip()
    fill_circle(26, 30, 13, HALO2)
    fill_circle(26, 30, 9, SUN)
    text("DigiCure", 48, 22, CREAM, 2)
    btn("lock", 182, 16, 48, 24, "LOCK", r=8)
    for name, tx, ty in TILES:
        if _current_y == 0:
            _btns.append((name, tx, ty, TILE_W, TILE_H))
        rrect(tx, ty, TILE_W, TILE_H, 14, KEY_BG)
        icon(name, tx + TILE_W // 2, ty + 34)
        textc(name, ty + 72, INK, 1, tx + TILE_W // 2)


# ---------------- list ----------------
_lmode = "all"
_page = 0
_view = []
_cur = 0
_show = False
_arm = False


def refresh_view():
    global _view
    _view = sorted(
        [i for i, e in enumerate(entries)
         if _lmode == "all" or e.get("f")],
        key=lambda i: entries[i]["n"].lower())


def open_list(mode):
    global _lmode, _page
    _lmode = mode
    _page = 0
    refresh_view()
    go("list")


def draw_list_strip():
    draw_sky_strip()
    textc("Passwords" if _lmode == "all" else "Favorites", 16, CREAM, 2)
    n = len(_view)
    if n == 0:
        textc("Nothing here yet", 110, CREAM, 1)
    start = _page * ROWS
    for k in range(ROWS):
        j = start + k
        if j >= n:
            break
        e = entries[_view[j]]
        y = 52 + k * 40
        bid = "r%d" % k
        if _current_y == 0:
            _btns.append((bid, 12, y, 216, 34))
        rrect(12, y, 216, 34, 10, KEY_BG)
        text(clip(e["n"], 22), 24, y + 13, INK, 1)
        if e.get("f"):
            fill_circle(212, y + 17, 5, HALO1)
    btn("back", 12, 226, 70, 36, "BACK")
    if _page > 0:
        btn("prev", 92, 226, 56, 36, "<")
    if start + ROWS < n:
        btn("next", 158, 226, 70, 36, ">")


# ---------------- detail ----------------
def draw_detail_strip():
    draw_sky_strip()
    e = entries[_cur]
    textc(clip(e["n"], 14), 14, CREAM, 2)
    text("User", 14, 50, CREAM, 1)
    text(clip(e["u"] or "-", 28), 14, 62, CREAM, 1)
    text("Password", 14, 86, CREAM, 1)
    pw = e["p"]
    shown = clip(pw, 28) if _show else "*" * min(len(pw), 28)
    text(shown, 14, 98, CREAM, 1)
    btn("tuser", 12, 124, 104, 40, "TYPE USER")
    btn("tpass", 124, 124, 104, 40, "TYPE PASS")
    btn("show", 12, 174, 104, 34, "HIDE" if _show else "SHOW")
    btn("fav", 124, 174, 104, 34, "UNFAV" if e.get("f") else "FAV")
    btn("del", 12, 220, 104, 34, "SURE?" if _arm else "DELETE",
        bg=RED if _arm else None, fg=CREAM if _arm else None)
    btn("back", 124, 220, 104, 34, "BACK")


def do_type(what):
    e = entries[_cur]
    s = e["u"] if what == "u" else e["p"]
    if not s:
        return
    if not hid_init():
        show_msg("No USB keys", "Install usb-device-keyboard")
        time.sleep_ms(2500)
        go("detail")
        return
    for n in (3, 2, 1):
        show_msg("Click field", "Typing in %d" % n)
        time.sleep_ms(1000)
    ok = type_text(s)
    show_msg("Typed" if ok else "Not connected")
    time.sleep_ms(900)
    go("detail")


# ---------------- add ----------------
def draw_add_strip():
    draw_sky_strip()
    textc("Add password", 16, CREAM, 2)
    btn("wifi", 12, 70, 216, 56, "ADD VIA WI-FI", sc=2)
    textc("Phone or laptop fills the form,", 146, CREAM, 1)
    textc("you approve on this screen", 160, CREAM, 1)
    btn("back", 60, 222, 120, 40, "BACK")


def start_wifi():
    try:
        wifi_start()
    except Exception as e:
        print("wifi error:", e)
        wifi_stop()
        show_msg("Wi-Fi error", clip(str(e), 28))
        time.sleep_ms(2500)
        go("add")
        return
    go("wifi")


def draw_wifi_strip():
    draw_sky_strip()
    textc("Add via Wi-Fi", 10, CREAM, 2)
    text("1. Join this Wi-Fi:", 12, 46, CREAM, 1)
    text(_ssid, 12, 60, CREAM, 2)
    text("Password:", 12, 88, CREAM, 1)
    text(_apw, 12, 102, CREAM, 2)
    text("2. Open in browser:", 12, 132, CREAM, 1)
    text("http://192.168.4.1", 12, 146, CREAM, 1)
    text("Waiting... %d s" % _wleft, 12, 176, CREAM, 1)
    btn("cancel", 60, 220, 120, 40, "CANCEL")


def wifi_tick():
    global _pending, _wleft
    left = time.ticks_diff(_wifi_deadline, time.ticks_ms())
    if left <= 0:
        wifi_stop()
        show_msg("Timed out")
        time.sleep_ms(1200)
        go("add")
        return
    secs = left // 1000
    if secs != _wleft:
        _wleft = secs
        redraw()
    req = wifi_poll()
    if req:
        _pending = req
        time.sleep_ms(300)
        wifi_stop()
        go("review")


def draw_confdel_strip():
    draw_sky_strip()
    textc("Delete?", 14, RED, 2)
    text(clip(entries[_link_del]["n"], 28), 14, 70, CREAM, 1)
    text("Requested from the website", 14, 96, CREAM, 1)
    btn("yes", 12, 200, 104, 44, "DELETE", bg=RED, fg=CREAM)
    btn("no", 124, 200, 104, 44, "CANCEL")


def draw_review_strip():
    draw_sky_strip()
    textc("Save this?", 14, CREAM, 2)
    p = _pending
    text("Name", 14, 60, CREAM, 1)
    text(clip(p["n"], 28), 14, 72, CREAM, 1)
    text("User", 14, 96, CREAM, 1)
    text(clip(p["u"] or "-", 28), 14, 108, CREAM, 1)
    text("Password: %d characters" % len(p["p"]), 14, 132, CREAM, 1)
    btn("save", 12, 200, 104, 44, "SAVE")
    btn("drop", 124, 200, 104, 44, "DISCARD")


# ---------------- settings / about ----------------
def draw_settings_strip():
    draw_sky_strip()
    textc("Settings", 16, CREAM, 2)
    btn("pin", 12, 64, 216, 44, "CHANGE PIN", sc=1)
    btn("about", 12, 118, 216, 44, "ABOUT", sc=1)
    btn("back", 60, 220, 120, 40, "BACK")


def draw_about_strip():
    draw_sky_strip()
    textc("DigiCure", 16, CREAM, 2)
    gc.collect()
    text("Entries: %d" % len(entries), 14, 64, CREAM, 1)
    text("Free RAM: %d KB" % (gc.mem_free() // 1024), 14, 82, CREAM, 1)
    text("PSRAM: %s" % ("yes" if HAS_PSRAM else "no"), 14, 100, CREAM, 1)
    text("Display: %s" % (
        "full frame" if STRIP_H == H else "%d-row strips" % STRIP_H),
        14, 118, CREAM, 1)
    text("Vault: AES-256 + HMAC", 14, 136, CREAM, 1)
    btn("back", 60, 220, 120, 40, "BACK")


DRAW = {
    "pin": draw_pin_strip,
    "home": draw_home_strip,
    "list": draw_list_strip,
    "detail": draw_detail_strip,
    "add": draw_add_strip,
    "wifi": draw_wifi_strip,
    "review": draw_review_strip,
    "confdel": draw_confdel_strip,
    "settings": draw_settings_strip,
    "about": draw_about_strip,
}


# ============================================================
# TAP HANDLING
# ============================================================


def dispatch(bid):
    global _page, _cur, _show, _arm, _pin_mode, _pin_digits, _pending
    global _link_add, _link_del
    if S == "pin":
        pin_key(bid)

    elif S == "home":
        if bid == "lock":
            go_lock()
        elif bid == "Passwords":
            open_list("all")
        elif bid == "Favorites":
            open_list("fav")
        elif bid == "Add":
            go("add")
        elif bid == "Settings":
            go("settings")

    elif S == "list":
        if bid == "back":
            go("home")
        elif bid == "prev":
            _page = max(0, _page - 1)
            go("list")
        elif bid == "next":
            _page += 1
            go("list")
        elif bid[0] == "r":
            idx = _page * ROWS + int(bid[1:])
            if idx < len(_view):
                _cur = _view[idx]
                _show = False
                _arm = False
                go("detail")

    elif S == "detail":
        if bid != "del":
            _arm = False
        if bid == "back":
            refresh_view()
            go("list")
        elif bid == "show":
            _show = not _show
            go("detail")
        elif bid == "fav":
            e = entries[_cur]
            e["f"] = 0 if e.get("f") else 1
            save_vault()
            go("detail")
        elif bid == "del":
            if _arm:
                entries.pop(_cur)
                save_vault()
                _arm = False
                refresh_view()
                _page = max(0, min(_page, (len(_view) - 1) // ROWS))
                go("list")
            else:
                _arm = True
                go("detail")
        elif bid == "tuser":
            do_type("u")
        elif bid == "tpass":
            do_type("p")

    elif S == "add":
        if bid == "wifi":
            start_wifi()
        elif bid == "back":
            go("home")

    elif S == "wifi":
        if bid == "cancel":
            wifi_stop()
            go("add")

    elif S == "review":
        if bid == "save":
            entries.append(_pending)
            _pending = None
            save_vault()
            if _link_add:
                _link_add = False
                link_send({"r": "add", "ok": 1})
            show_msg("Saved")
            time.sleep_ms(900)
            go("home")
        elif bid == "drop":
            _pending = None
            if _link_add:
                _link_add = False
                link_send({"r": "add", "ok": 0})
                go("home")
            else:
                go("add")

    elif S == "confdel":
        if bid == "yes" and 0 <= _link_del < len(entries):
            entries.pop(_link_del)
            save_vault()
            link_send({"r": "del", "ok": 1})
        else:
            link_send({"r": "del", "ok": 0})
        _link_del = -1
        go("home")

    elif S == "settings":
        if bid == "pin":
            _pin_mode = "new1"
            _pin_digits = ""
            go("pin")
        elif bid == "about":
            go("about")
        elif bid == "back":
            go("home")

    elif S == "about":
        if bid == "back":
            go("settings")


# ============================================================
# MAIN
# ============================================================


def main():
    global _lock_frame, _lkey
    lcd_init()
    touch_init()
    recover_vault()
    print("DigiCure: display", "full" if STRIP_H == H else STRIP_H,
          "rows | PSRAM heap:", HAS_PSRAM, "| free:", gc.mem_free())

    was_down = False

    while True:
        pt = touch()
        tap = pt is not None and not was_down
        was_down = pt is not None
        link_poll()

        if S == "lock":
            blink = (_lock_frame // 18) % 2 if _lock_frame > RISE_FRAMES else 0
            key = (min(_lock_frame, RISE_FRAMES),
                   int(3 * math.sin(_lock_frame / 8)), blink)
            if key != _lkey:
                _lkey = key
                render_screen(draw_lock_strip)
            _lock_frame += 1
            if tap:
                open_pin()
        else:
            if S == "wifi":
                wifi_tick()
            if D:
                redraw()
            if tap:
                for bid, x, y, w, h in _btns:
                    if hit(pt, x, y, w, h):
                        dispatch(bid)
                        break

        time.sleep_ms(10)


gc.collect()

try:
    main()
except KeyboardInterrupt:
    wifi_stop()
    raise
except Exception as e:
    import sys
    wifi_stop()
    sys.print_exception(e)
    raise
