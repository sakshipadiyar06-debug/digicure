import machine
from machine import Pin, SPI, I2C
import framebuf
import time
import math
import gc
import os
import json
import sys
import select
import binascii

try:
    import hashlib
except ImportError:
    import uhashlib as hashlib

try:
    import cryptolib as _cl
except ImportError:
    import ucryptolib as _cl

gc.collect()
HAS_PSRAM = gc.mem_free() > 1_000_000
if HAS_PSRAM:
    # Collect less often now that there's real headroom. This reduces
    # GC-pause collisions with the Bluetooth task during handshakes.
    gc.threshold(gc.mem_free() // 4 + gc.mem_alloc())

# ============================================================
# SETTINGS
# ============================================================

PIN_LEN = 4            # changing this later means a new vault
KDF_ROUNDS = 3000
VAULT_FILE = "/vault.enc"
FAIL_FILE = "/fails.txt"
ERR_FILE = "/err.txt"
ROWS = 4               # entries per page

W = 240
H = 280
Y_OFF = 20

# ============================================================
# MEMORY TRACKING (shown on the ABOUT screen)
# ============================================================

_min_free = 1 << 30     # lowest free heap ever seen this boot
_boot_free = 0          # free heap right after the display buffer is ready


def track_mem():
    global _min_free
    f = gc.mem_free()
    if f < _min_free:
        _min_free = f


track_mem()


# ============================================================
# FRAMEBUFFER (adaptive, full-size whenever it fits)
# ============================================================

buf = None
fb = None
STRIP_H = 20


def alloc_fb():
    global buf, fb, STRIP_H
    # Try the full screen first - this now succeeds in both USB and BLE
    # mode on PSRAM firmware. Smaller strips are only a fallback if this
    # firmware somehow doesn't have PSRAM after all.
    for h in (280, 140, 70, 40, 20, 10):
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


# ============================================================
# BLUETOOTH KEYBOARD (BLE HID)
# ============================================================

BT_NAME = "DigiCure"
BOND_FILE = "/bonds.json"
MODE_FILE = "/mode.txt"

_type_mode = "usb"
_ble = None
_bt_h = None
_bt_conn = None
_bt_enc = False
_bt_pass = 0
_bt_err = ""
_bt_tried = False
_bt_dirty = False
_bt_bonds = {}
_adv_on = False          # True while we are advertising
_adv_t = 0               # last time we (re)started advertising
_bg_conn_t = None        # when the current background connection began
_bg_pair_t = 0           # last time we asked the PC to secure the link
_bt_stat = ""            # status text shown on the password screen

# Standard keyboard: 1 modifier byte, 1 reserved byte, 6 key codes
_HID_MAP = bytes([
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01,
    0x75, 0x08, 0x81, 0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65,
    0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xC0])


STEP_FILE = "/step.txt"
_bt_last = 0
_bt_last_ms = 0


BT_FILE = "/bterr.txt"


def crumb(t, fn=None):
    # Remember the last step reached, so we can see where a restart happened.
    try:
        with open(fn or STEP_FILE, "w") as f:
            f.write(t)
    except OSError:
        pass


def last_bt():
    try:
        with open(BT_FILE) as f:
            return f.read().strip() or "none"
    except OSError:
        return "none"


def load_mode():
    global _type_mode
    try:
        with open(MODE_FILE) as f:
            _type_mode = "ble" if f.read().strip() == "ble" else "usb"
    except OSError:
        _type_mode = "usb"


def save_mode():
    try:
        with open(MODE_FILE, "w") as f:
            f.write(_type_mode)
    except OSError:
        pass


def bt_load():
    global _bt_bonds
    _bt_bonds = {}
    try:
        with open(BOND_FILE) as f:
            d = json.load(f)
        for k, v in d.items():
            t, h = k.split(":")
            _bt_bonds[(int(t), binascii.unhexlify(h))] = binascii.unhexlify(v)
    except Exception:
        _bt_bonds = {}


def bt_save():
    try:
        d = {}
        for (t, k), v in _bt_bonds.items():
            d["%d:%s" % (t, binascii.hexlify(k).decode())] = \
                binascii.hexlify(v).decode()
        with open(BOND_FILE, "w") as f:
            json.dump(d, f)
    except Exception as e:
        print("bond save error:", e)


def _bt_irq_inner(event, data):
    global _bt_conn, _bt_enc, _bt_pass, _bt_dirty, _adv_on
    if event == 1:                      # central connected
        _bt_conn = data[0]
        _bt_enc = False
        _adv_on = False                 # advertising stops on connect
    elif event == 2:                    # central disconnected
        _bt_conn = None
        _bt_enc = False
        _adv_on = False
    elif event == 28:                   # encryption update
        _bt_enc = bool(data[1])
    elif event == 29:                   # get secret
        sec_type, index, key = data
        if key is None:
            i = 0
            for (t, k), v in _bt_bonds.items():
                if t == sec_type:
                    if i == index:
                        return v
                    i += 1
            return None
        return _bt_bonds.get((sec_type, bytes(key)))
    elif event == 30:                   # set secret
        sec_type, key, value = data
        k = (sec_type, bytes(key))
        if value is None:
            if k in _bt_bonds:
                del _bt_bonds[k]
                _bt_dirty = True
                return True
            return False
        _bt_bonds[k] = bytes(value)
        _bt_dirty = True
        return True
    elif event == 31:                   # passkey action
        conn, action, passkey = data
        if action == 3:                 # we display the passkey
            _bt_pass = int.from_bytes(os.urandom(4), "big") % 1000000
            _ble.gap_passkey(conn, action, _bt_pass)


def _bt_irq(event, data):
    # Bluetooth callbacks must never raise or touch the filesystem.
    global _bt_last, _bt_last_ms
    _bt_last = event
    _bt_last_ms = time.ticks_ms()
    try:
        return _bt_irq_inner(event, data)
    except Exception:
        return None


def bt_flush():
    # Save pairing keys from the main program, not from the callback.
    global _bt_dirty
    if _bt_dirty and _bt_conn is None:
        _bt_dirty = False
        bt_save()


def bt_saved_count():
    try:
        with open(BOND_FILE) as f:
            return len(json.load(f))
    except Exception:
        return 0


def bt_finish():
    # New pairing keys must reach flash, or the PC and the board forget each
    # other when power is cut. Flash is only written while no connection is
    # open, so close the link first; Windows reconnects by itself next time.
    if not _bt_dirty:
        return
    bt_adv_stop()
    if _bt_conn is not None:
        try:
            _ble.gap_disconnect(_bt_conn)
        except Exception:
            pass
        t = 30
        while _bt_conn is not None and t > 0:
            time.sleep_ms(100)
            t -= 1
    bt_flush()


def bt_init():
    global _ble, _bt_h, _bt_err, _bt_tried
    if _ble is not None:
        return True
    if _bt_tried:
        return False        # never start Bluetooth twice in one boot
    _bt_tried = True
    st = "import"
    crumb("init " + st, BT_FILE)
    try:
        import bluetooth
        gc.collect()
        bt_load()
        st = "BLE()"
        crumb("init " + st, BT_FILE)
        ble = bluetooth.BLE()
        st = "active"
        crumb("init " + st, BT_FILE)
        try:
            ble.active(True)
        except OSError:
            gc.collect()
            try:
                ble.active(False)
            except Exception:
                pass
            time.sleep_ms(300)
            ble.active(True)
        st = "config"
        crumb("init " + st, BT_FILE)
        try:
            ble.config(gap_name=BT_NAME)
        except Exception:
            pass
        try:
            # Simple pairing: this is the setup proven to work in ble_test4.py
            ble.config(bond=True, mitm=False, le_secure=True, io=3)
        except Exception as e:
            print("BLE security config:", e)
        st = "irq"
        crumb("init " + st, BT_FILE)
        ble.irq(_bt_irq)
        st = "services"
        crumb("init " + st, BT_FILE)
        U = bluetooth.UUID
        dis = (U(0x180A), (
            (U(0x2A29), bluetooth.FLAG_READ),
            (U(0x2A24), bluetooth.FLAG_READ),
            (U(0x2A50), bluetooth.FLAG_READ),
        ))
        hid = (U(0x1812), (
         (U(0x2A4A), bluetooth.FLAG_READ),
         (U(0x2A4B), bluetooth.FLAG_READ),
         (U(0x2A4C), bluetooth.FLAG_WRITE_NO_RESPONSE),
         (U(0x2A4D), bluetooth.FLAG_READ | bluetooth.FLAG_NOTIFY,
         ((U(0x2908), bluetooth.FLAG_READ),)),
         (U(0x2A4E), bluetooth.FLAG_READ
     | bluetooth.FLAG_WRITE_NO_RESPONSE),
))

        bat = (U(0x180F), ((U(0x2A19),
                            bluetooth.FLAG_READ | bluetooth.FLAG_NOTIFY),))
        d, h, b = ble.gatts_register_services((dis, hid, bat))
        st = "write"
        crumb("init " + st, BT_FILE)
        ble.gatts_write(d[0], b"DigiCure")
        ble.gatts_write(d[1], b"DigiCure")
        ble.gatts_write(d[2], b"\x02\x09\x12\x01\x00\x01\x00")
        ble.gatts_write(h[0], b"\x11\x01\x00\x02")
        ble.gatts_write(h[1], _HID_MAP)
        ble.gatts_write(h[3], bytes(8))
        ble.gatts_write(h[4], b"\x00\x01")
        ble.gatts_write(h[5], b"\x01")
        ble.gatts_write(b[0], b"\x64")
        _bt_h = h[3]
        _ble = ble
        crumb("init ok", BT_FILE)
        return True
    except Exception as e:
        _bt_err = "%s %s: %s" % (st, type(e).__name__, e)
        print("BLE unavailable:", _bt_err)
        crumb("%s %s%s free=%dK" % (st, type(e).__name__[:2],
                                    e.args[0] if e.args else "",
                                    gc.mem_free() // 1024), BT_FILE)
        try:
            import bluetooth
            bluetooth.BLE().active(False)
        except Exception:
            pass
        _ble = None
        return False


def bt_adv():
    global _adv_on
    name = BT_NAME.encode()
    adv = b"\x02\x01\x06" + b"\x03\x19\xc1\x03" + b"\x03\x03\x12\x18"
    resp = bytes([len(name) + 1, 9]) + name
    _ble.gap_advertise(100000, adv_data=adv, resp_data=resp)
    _adv_on = True


def bt_adv_stop():
    global _adv_on
    _adv_on = False
    try:
        _ble.gap_advertise(None)
    except Exception:
        pass


def bt_type_text(s):
    try:
        # Give Windows time to subscribe to HID notifications.
        time.sleep_ms(300)

        if _bt_conn is None:
            return False

        for ch in s:
            code, shift = hid_code(ch)

            if code is None:
                continue

            # Key down
            _ble.gatts_notify(
                _bt_conn,
                _bt_h,
                bytes([
                    2 if shift else 0,
                    0,
                    code,
                    0,
                    0,
                    0,
                    0,
                    0
                ])
            )

            time.sleep_ms(40)

            # Key up
            _ble.gatts_notify(
                _bt_conn,
                _bt_h,
                bytes(8)
            )

            time.sleep_ms(80)

        # Always send a final key-up report.
        _ble.gatts_notify(
            _bt_conn,
            _bt_h,
            bytes(8)
        )

        return True

    except Exception as e:
        print("BLE type error:", e)
        return False



def bt_reset():
    global _bt_bonds
    _bt_bonds = {}
    try:
        os.remove(BOND_FILE)
    except OSError:
        pass
    if _ble is not None and _bt_conn is not None:
        try:
            _ble.gap_disconnect(_bt_conn)
        except Exception:
            pass


def bt_drop():
    # Stop advertising and cut any live link (used when locking).
    if _ble is None:
        return
    bt_adv_stop()
    if _bt_conn is not None:
        try:
            _ble.gap_disconnect(_bt_conn)
        except Exception:
            pass


def bt_bg():
    # Background BLE connection manager.
    # No pairing/security wait is performed here.
    #
    # While unlocked and in BLE mode:
    #   - advertise when no PC is connected
    #   - keep an existing connection
    #   - report ready immediately after connection

    global _adv_t, _bg_conn_t, _bt_stat, D

    if _ble is None or _type_mode != "ble":
        return

    now = time.ticks_ms()

    if _ke is None:
        if _adv_on:
            bt_adv_stop()
        stat = ""

    elif _bt_conn is None:
        _bg_conn_t = None

        if not _adv_on and time.ticks_diff(now, _adv_t) > 3000:
            _adv_t = now
            try:
                bt_adv()
            except Exception as e:
                print("bg adv:", e)

        stat = "Bluetooth: waiting for PC"

    else:
        if _bg_conn_t is None:
            _bg_conn_t = now

        # IMPORTANT:
        # No gap_pair()
        # No _bt_enc wait
        # No "securing..." state.
        stat = "Bluetooth: ready"

    if stat != _bt_stat:
        _bt_stat = stat
        if S == "detail":
            D = True



# Bluetooth still starts before the display claims its buffer. This is no
# longer required to dodge "active OSError 5" (PSRAM gives plenty of room
# for both), but starting the radio early still means it's ready sooner,
# so a "type" request just after boot doesn't have to wait on bt_init().
load_mode()
if _type_mode == "ble":
    bt_init()
alloc_fb()
gc.collect()
_boot_free = gc.mem_free()
track_mem()

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
        if STRIP_H < H:
            time.sleep_ms(1)   # let the Bluetooth task run between strips
            # (only needed when STRIP_H < H; with the full-size buffer
            # there's only one "strip" per screen, so this never fires)


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
    for i in range(KDF_ROUNDS):
        k = sha256(k + salt + p).digest()
        if i % 250 == 0:
            time.sleep_ms(1)
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


def vault_salt():
    try:
        with open(VAULT_FILE, "rb") as f:
            b = f.read(19)
        if len(b) == 19 and b[:3] == MAGIC:
            return binascii.hexlify(b[3:19]).decode()
    except OSError:
        pass
    return None


def load_keys(ke, km):
    global entries, _ke, _km, _salt
    with open(VAULT_FILE, "rb") as f:
        blob = f.read()
    if blob[:3] != MAGIC or len(blob) < 3 + 16 + 16 + 16 + 32:
        return False
    salt = blob[3:19]
    iv = blob[19:35]
    ct = blob[35:-32]
    mac = blob[-32:]
    if len(ct) % 16 or not ct_eq(hmac256(km, blob[:-32]), mac):
        return False
    pt = _cl.aes(ke, 2, iv).decrypt(ct)
    pad = pt[-1]
    entries = json.loads(pt[:-pad])
    _ke, _km, _salt = ke, km, salt
    return True


def load_vault(pin):
    s = vault_salt()
    if not s:
        return False
    ke, km = derive(pin, binascii.unhexlify(s))
    return load_keys(ke, km)


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


def _kb_send(k, down, up):
    # send_keys returns False when the report could not be queued in time;
    # retry then, so a key-up is never lost.
    for _ in range(40):
        try:
            r = k.send_keys(down, up) if up else k.send_keys(down)
        except Exception as e:
            print("HID send error:", e)
            return False
        if r is not False:
            return True
        time.sleep_ms(5)
    return False


def _send_rep(k, rep):
    # Send one raw 8-byte keyboard report, retrying while the USB
    # endpoint is busy. Raw reports avoid the library's key-state
    # tracking, which could leave a key "held down" (repeating).
    for _ in range(10):
        try:
            if k.send_report(rep):
                return True
        except Exception as e:
            print("HID send error:", e)
            return False
        time.sleep_ms(10)
    return False


def type_text(s):
    k = _kbd
    t = 30
    while not k.is_open() and t > 0:
        time.sleep_ms(100)
        t -= 1
    if not k.is_open():
        return False
    ok = True
    try:
        for ch in s:
            code, shift = hid_code(ch)
            if code is None:
                continue
            rep = bytes([2 if shift else 0, 0, code, 0, 0, 0, 0, 0])
            if not _send_rep(k, rep):
                ok = False
                break
            time.sleep_ms(25)
            if not _send_rep(k, bytes(8)):
                ok = False
                break
            time.sleep_ms(25)
    finally:
        # always make sure no key is left pressed
        _send_rep(k, bytes(8))
    return ok


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


def after_action():
    go("home")


# ---------------- USB serial link (used by the website) ----------------
# Lines look like  DC{"c":"list"}  (host -> device) and
# DC{"r":"list",...}  (device -> host). The PIN is never sent over USB.
_poll = select.poll()
_poll.register(sys.stdin, select.POLLIN)
_rx = ""
_link_add = False
_link_del = -1
_link_reveal = -1
_pending = None
_BUSY = ("review", "confdel", "confreveal", "pin")


def link_send(d):
    print("DC" + json.dumps(d))


def do_login(m):
    global _lkey
    if _ke is not None:
        link_send({"r": "login", "ok": 1})
        return
    if S not in ("lock", "pin") or not vault_exists():
        link_send({"r": "login", "err": "busy"})
        return
    ok = False
    try:
        ok = load_keys(binascii.unhexlify(m["ke"]),
                       binascii.unhexlify(m["km"]))
    except Exception as e:
        print("login error:", e)
    if ok:
        set_fails(0)
        link_send({"r": "login", "ok": 1})
        go("home")
        return
    n = get_fails() + 1
    set_fails(n)
    p = penalty(n)
    link_send({"r": "login", "err": "wrong", "wait": p})
    if p:
        lockout_wait(p)
        _lkey = None
        go(S)


def link_cmd(m):
    global _pending, _link_add, _link_del, _link_reveal
    c = m.get("c")
    if c == "hello":
        link_send({"r": "hello", "locked": _ke is None, "n": len(entries),
                   "m": _type_mode})
    elif c == "salt":
        s = vault_salt()
        if s:
            link_send({"r": "salt", "s": s, "rounds": KDF_ROUNDS})
        else:
            link_send({"r": "salt", "err": "novault"})
    elif c == "login":
        do_login(m)
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
    elif c == "reveal":
        i = m.get("i", -1)
        if isinstance(i, int) and 0 <= i < len(entries):
            _link_reveal = i
            go("confreveal")
        else:
            link_send({"r": "reveal", "err": "bad"})


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


def do_type_ble(s):
    if not bt_init():
        show_msg("Bluetooth error", clip(_bt_err, 28), clip(_bt_err[28:], 28))
        time.sleep_ms(4000)
        go("detail")
        return
    # Bluetooth callbacks run Python code in the Bluetooth task, at the same
    # time as this program. Pause the garbage collector while Bluetooth is
    # busy so the two can never collide in memory. Still worth doing even
    # with PSRAM - this is a concurrency guard, not a memory-size one.
    gc.collect()
    gc.disable()
    try:
        _do_type_ble(s)
    finally:
        gc.enable()
    track_mem()
    gc.collect()


def _do_type_ble(s):
    global _bt_pass

    # Wait for the TYPE button touch to be released.
    while touch() is not None:
        time.sleep_ms(20)

    _bt_pass = 0

    # ------------------------------------------------------------
    # If not connected, advertise and wait for connection.
    # ------------------------------------------------------------
    if _bt_conn is None:
        try:
            bt_adv()
        except Exception as e:
            show_msg("BLE error", clip(str(e), 28))
            time.sleep_ms(2000)
            go("detail")
            return

        show_msg("Waiting for PC", "Connect to DigiCure")

        end = time.ticks_add(time.ticks_ms(), 60000)

        while _bt_conn is None:
            if time.ticks_diff(end, time.ticks_ms()) <= 0:
                bt_adv_stop()
                show_msg("Not connected")
                time.sleep_ms(1000)
                go("detail")
                return

            time.sleep_ms(100)

    # ------------------------------------------------------------
    # CONNECTED
    #
    # Do NOT wait for encryption.
    # Do NOT call gap_pair().
    # ------------------------------------------------------------

    bt_adv_stop()

    show_msg("Connected", "Preparing keyboard...")
    time.sleep_ms(500)

    # Make sure connection still exists.
    if _bt_conn is None:
        show_msg("Disconnected")
        time.sleep_ms(800)
        go("detail")
        return

    # ------------------------------------------------------------
    # TYPE
    # ------------------------------------------------------------

    show_msg("Typing...")
    time.sleep_ms(300)

    ok = bt_type_text(s)

    if ok:
        show_msg("Typed")
    else:
        show_msg("Typing failed")

    time.sleep_ms(1000)
    go("detail")



def do_type(what):
    e = entries[_cur]
    s = e["u"] if what == "u" else e["p"]
    if not s:
        return
    if _type_mode == "ble":
        do_type_ble(s)
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
    text("Use the DigiCure website:", 14, 70, CREAM, 1)
    text("1. Plug in the USB cable", 14, 92, CREAM, 1)
    text("2. Open the site, Connect", 14, 108, CREAM, 1)
    text("3. Add it, then tap SAVE", 14, 124, CREAM, 1)
    text("   on this screen", 14, 140, CREAM, 1)
    btn("back", 60, 222, 120, 40, "BACK")


def draw_confdel_strip():
    draw_sky_strip()
    textc("Delete?", 14, RED, 2)
    text(clip(entries[_link_del]["n"], 28), 14, 70, CREAM, 1)
    text("Requested from the website", 14, 96, CREAM, 1)
    btn("yes", 12, 200, 104, 44, "DELETE", bg=RED, fg=CREAM)
    btn("no", 124, 200, 104, 44, "CANCEL")


def draw_confreveal_strip():
    draw_sky_strip()
    textc("Send password?", 14, RED, 2)
    text(clip(entries[_link_reveal]["n"], 28), 14, 70, CREAM, 1)
    text("Requested over USB cable", 14, 96, CREAM, 1)
    btn("yes", 12, 200, 104, 44, "ALLOW", bg=RED, fg=CREAM)
    btn("no", 124, 200, 104, 44, "DENY")


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
    btn("pin", 12, 52, 216, 38, "CHANGE PIN")
    btn("about", 12, 96, 216, 38, "ABOUT")
    btn("mode", 12, 140, 216, 38,
        "TYPE VIA: " + ("BLUETOOTH" if _type_mode == "ble" else "USB"))
    btn("btreset", 12, 184, 216, 38, "NEW BLUETOOTH DEVICE")
    btn("back", 60, 228, 120, 34, "BACK")


def last_err():
    try:
        with open(ERR_FILE) as f:
            lines = f.read().strip().split("\n")
        return lines[-1] if lines and lines[-1] else "none"
    except OSError:
        return "none"


def draw_about_strip():
    draw_sky_strip()
    textc("DigiCure v12", 14, CREAM, 2)
    # Memory numbers (taken once, after a collect, so "used" = live data)
    track_mem()
    gc.collect()
    free = gc.mem_free()
    used = gc.mem_alloc()
    total = free + used
    low = min(_min_free, free)
    y = 40
    text("Entries: %d" % len(entries), 14, y, CREAM, 1)
    y += 16
    text("Used: %d / %d KB" % (used // 1024, total // 1024), 14, y, CREAM, 1)
    y += 16
    text("Free: %d KB  Low: %d KB" % (free // 1024, low // 1024),
         14, y, CREAM, 1)
    y += 16
    text("Screen buf: %d KB" % (len(buf) // 1024), 14, y, CREAM, 1)
    y += 16
    text("Saved keys: %d" % bt_saved_count(), 14, y, CREAM, 1)
    y += 16
    text("Display: %s" % (
        "full frame" if STRIP_H == H else "%d-row strips" % STRIP_H),
        14, y, CREAM, 1)
    y += 16
    text("BT: " + clip(last_bt(), 24), 14, y, CREAM, 1)
    y += 16
    text("Reset: %s  Mode: %s" % (machine.reset_cause(), _type_mode),
         14, y, CREAM, 1)
    y += 16
    text("Err: " + clip(last_err(), 23), 14, y, CREAM, 1)
    btn("back", 60, 226, 120, 36, "BACK")


DRAW = {
    "pin": draw_pin_strip,
    "home": draw_home_strip,
    "list": draw_list_strip,
    "detail": draw_detail_strip,
    "add": draw_add_strip,
    "review": draw_review_strip,
    "confdel": draw_confdel_strip,
    "confreveal": draw_confreveal_strip,
    "settings": draw_settings_strip,
    "about": draw_about_strip,
}


# ============================================================
# TAP HANDLING
# ============================================================


def dispatch(bid):
    global _page, _cur, _show, _arm, _pin_mode, _pin_digits, _pending
    global _link_add, _link_del, _link_reveal, _type_mode
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
        if bid == "back":
            go("home")

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
            after_action()
        elif bid == "drop":
            _pending = None
            if _link_add:
                _link_add = False
                link_send({"r": "add", "ok": 0})
                after_action()
            else:
                go("home")

    elif S == "confdel":
        if bid == "yes" and 0 <= _link_del < len(entries):
            entries.pop(_link_del)
            save_vault()
            link_send({"r": "del", "ok": 1})
        else:
            link_send({"r": "del", "ok": 0})
        _link_del = -1
        after_action()

    elif S == "confreveal":
        if bid == "yes" and 0 <= _link_reveal < len(entries):
            link_send({"r": "reveal", "ok": 1,
                       "p": entries[_link_reveal]["p"]})
        else:
            link_send({"r": "reveal", "ok": 0})
        _link_reveal = -1
        after_action()

    elif S == "settings":
        if bid == "pin":
            _pin_mode = "new1"
            _pin_digits = ""
            go("pin")
        elif bid == "about":
            go("about")
        elif bid == "mode":
            _type_mode = "ble" if _type_mode == "usb" else "usb"
            save_mode()
            show_msg("Restarting...",
                     "Mode: " + ("BLUETOOTH" if _type_mode == "ble" else "USB"))
            time.sleep_ms(900)
            machine.reset()
        elif bid == "btreset":
            if _bt_bonds or bt_saved_count():
                bt_reset()
                show_msg("Saved device removed", "On PC: remove DigiCure",
                         "then tap TYPE to pair")
            else:
                show_msg("No saved device", "Tap TYPE to pair one")
            time.sleep_ms(2200)
            go("settings")
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
    load_mode()
    print("DigiCure: display", "full" if STRIP_H == H else STRIP_H,
          "rows | PSRAM heap:", HAS_PSRAM, "| free:", gc.mem_free())

    was_down = False

    while True:
        pt = touch()
        tap = pt is not None and not was_down
        was_down = pt is not None
        link_poll()
        track_mem()
        if _bt_dirty:
            bt_flush()

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
    raise
except Exception as e:
    try:
        with open(ERR_FILE, "w") as f:
            sys.print_exception(e, f)
    except Exception:
        pass
    sys.print_exception(e)
    raise
