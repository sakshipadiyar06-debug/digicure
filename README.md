# 🌅 DigiCure

**An offline hardware password vault for the ESP32-S3.**
Your passwords live on a small touchscreen device, not in the cloud. When you need one, the device **types it for you** over USB or Bluetooth, like a keyboard.

> No accounts. No cloud. No app to install. Flash it, set a PIN, and use it.

**Live site (flasher and vault manager):** https://sakshipadiyar06-debug.github.io/digicure/

---

## ✨ Features

- 🖐️ **Touchscreen interface** on the device: PIN pad, password list, favorites, search by browsing, settings.
- ⌨️ **Types passwords for you** as a USB keyboard or a Bluetooth (BLE) keyboard. No clipboard, nothing to copy.
- 🌐 **Browser-based setup and manager** using Web Serial: flash MicroPython, upload the app, and add, view or delete credentials from your computer.
- ✋ **Physical approval:** adding, deleting or revealing a credential from the website always needs a tap on the device.
- 🚫 **Wrong-PIN lockout** that grows with every failed attempt and is remembered across restarts.
- 📴 **Fully offline:** the device has no WiFi code and the website only talks to your own board over the USB cable.

---

## 🧩 How it works

```
 ┌──────────────┐   USB cable (Web Serial)   ┌──────────────────┐
 │  Browser     │ ◄────────────────────────► │  ESP32-S3        │
 │  (this site) │   flash, upload, manage    │  DigiCure device │
 └──────────────┘                            │  encrypted vault │
                                             └───────┬──────────┘
                                                     │ types the password
                                          USB keyboard or Bluetooth keyboard
                                                     ▼
                                           Your computer or phone
```

- **Setup and management** go through the website and the USB cable only.
- **Typing** goes through USB or Bluetooth. Bluetooth is used *only* to send keystrokes. No vault data is sent over it.

---

## 🛠️ Hardware

| Part | Details |
| --- | --- |
| Board | ESP32-S3 (developed on the DigiComp N16R8 board) |
| Display | 240×280 ST7789, SPI |
| Touch | CST816T, I²C (address `0x15`) |
| Firmware | MicroPython **v1.29.0** (`ESP32_GENERIC_S3`), included in `firmware/` |

**Pins used (edit them at the top of `main.py` if your board differs):**

| Function | GPIO |
| --- | --- |
| LCD SCK / MOSI / CS / DC / RST / BL | 6 / 7 / 5 / 8 / 15 / 4 |
| Touch SDA / SCL / RST / IRQ | 11 / 12 / 9 / 10 |

---

## 🚀 Quick start

Use **Chrome, Edge, Opera or Brave** on a computer (Web Serial is required), and a USB **data** cable.

1. **Open the site:** https://sakshipadiyar06-debug.github.io/digicure/
2. **Step 1 – Flash MicroPython.** First time only. This erases the board.
3. **Step 3 – Connect Serial** and pick your board.
4. **Step 2 – Upload App.** This uploads `main.py` and restarts the device. An existing vault is kept.
5. On the device, tap to unlock and **choose a 4-digit PIN** (first boot).
6. Add credentials from the site (tap **SAVE** on the device to approve), or browse them on the device.

### USB typing (one-time package)

USB typing needs the MicroPython keyboard package on the board:

```
py -m mpremote connect COMx mip install usb-device-keyboard
```

(Replace `COMx` with your board's port.)

---

## 📶 Typing over Bluetooth

1. On the device open **Settings** and set **TYPE VIA** to **BLUETOOTH**. The device restarts.
2. On your computer, remove any old **DigiCure** entry in Bluetooth settings.
3. On the device, unlock, open a password and tap **TYPE USER** or **TYPE PASS**. Wait for *Pair 'DigiCure'*.
4. On your computer, choose **Add device → Bluetooth → DigiCure**.
5. Click the field you want to fill. The device types after a 3-second countdown.

**Next time** just tap TYPE. The device remembers the computer it was paired with and reconnects by itself.

**Switching computers:** Settings → **NEW BLUETOOTH DEVICE**, remove *DigiCure* on the old computer, then pair the new one.

**If it won't connect:** tap **NEW BLUETOOTH DEVICE** on the device *and* remove *DigiCure* on the computer, then pair again. Both sides must forget each other together. The **About** screen shows the app version, a **BT:** status line and the number of saved pairing keys, which helps when something goes wrong.

---

## 📁 Repository layout

| Path | What it is |
| --- | --- |
| `index.html` | The website: flasher, uploader and vault manager |
| `main.py` | The device application (this is what *Upload App* sends to the board) |
| `manifest.json` | Flasher manifest for the MicroPython image |
| `firmware/` | MicroPython `ESP32_GENERIC_S3` v1.29.0 image |

> **Note:** *Upload App* fetches `main.py` from this repository, so whatever `main.py` is committed here is what gets flashed to the device. Your passwords, PIN and Bluetooth pairings are stored **on each user's own board**, never in this repository.

---

## 🔒 Security notes (please read)

This is a learning and hobby project. It has **not** been independently audited.

- The vault key comes from a **4-digit PIN** with a modest number of hash rounds. The lockout stops guessing **on the device**, but someone who can read the board's flash chip could try PINs offline, and a 4-digit PIN can be guessed quickly that way. Treat the device like a physical key and don't leave it unattended.
- **Bluetooth pairing uses "Just Works"**, which protects against passive eavesdropping but not against an active attacker present *during* pairing. Pair in a safe place.
- Anything typed appears on the screen of the computer you type into. Only use computers you trust.
- Avoid storing your most critical accounts here until you are comfortable with these limits.

---

## 🧯 Troubleshooting

| Problem | Try this |
| --- | --- |
| Browser says Web Serial is unsupported | Use Chrome, Edge, Opera or Brave over HTTPS |
| Can't connect to the board | Use a data cable, close other programs using the port (Thonny, a terminal) |
| About screen shows an old version | Make sure the new `main.py` is committed to the repo, then click *Upload App* again |
| Bluetooth connects but nothing types | Remove *DigiCure* on the computer and tap **NEW BLUETOOTH DEVICE** on the device, then pair again |
| Typing is wrong or repeats | The device types slowly on purpose; click the target field before the countdown ends |

---

## 🗺️ Ideas for the future

- Stronger key derivation and longer PIN options
- Password generator on the device
- Auto-lock timer
- Backup and restore of the encrypted vault

---

## 🙏 Credits

Built with [MicroPython](https://micropython.org/) and [esp-web-tools](https://esphome.github.io/esp-web-tools/).
Created by **Sakshi** ([@sakshipadiyar06-debug](https://github.com/sakshipadiyar06-debug)).

## 📄 License

Add a `LICENSE` file to choose how others may use this project (MIT is a common, permissive choice).
