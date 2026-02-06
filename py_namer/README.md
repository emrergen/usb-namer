# USB Device Namer (Python)

A modern, graphical alternative to `namer.sh` for creating persistent udev rules for USB devices on Linux.

## Features

- **Graphical Interface**: View connected devices in a clean, sortable list.
- **Dynamic Detection**: Automatically refreshes the device list when new devices are plugged in.
- **Robust Identification**: Uses multiple strategies (`udevadm` properties, attribute walking) to find Vendor IDs, Product IDs, and Serial Numbers.
- **Safe Rule Creation**: Generates valid udev rules in `/etc/udev/rules.d/`.
- **Zero Dependencies**: Built with standard library `tkinter` and `subprocess`. No `pip install` required.

## Installation

No installation required using `pip`. Just ensure you have `python3-tk` installed (standard on most desktop distros).

On Ubuntu/Debian:
```bash
sudo apt-get install python3-tk
```

## Usage

**Important:** Creating udev rules requires `root` privileges. You must run the application with `sudo`.

1. **Run the application:**
   ```bash
   cd /path/to/usb_namer
   sudo python3 py_namer/main.py
   ```

2. **Create a Rule:**
   - Select a device from the list.
   - Enter a **Symlink Name** (e.g., `my_camera`).
   - Click **Create udev Rule**.
   - Review the success message.

3. **Apply Changes:**
   - Click **Reload udev Rules** in the app, or unplug/replug your device.
   - Check if the symlink exists: `ls -l /dev/my_camera`.

4. **Delete a Rule:**
   - Select a device with an existing symlink (visible in the list).
   - Click **Delete Rule**.
   - If multiple symlinks exist, select the one to remove.


## Troubleshooting

- **No Serial Number?**: Some cheap USB-Serial converters don't have unique serial numbers. The app will warn you and offer to create a rule based on Vendor/Product ID only (allowing multiple identical devices to match).
- **Not appearing in list?**: Ensure the device is recognized by the kernel (`dmesg` or `lsusb`).
- **Permission Denied**: Did you run with `sudo`?

## Structure

- `device_mgr.py`: Backend logic handling `udevadm` calls and rule generation.

## Standalone Binary (Tek Dosya)

Bu programı tek bir dosya olarak `dist/usb_namer` altında bulabilirsiniz.
Bu dosyayı istediğiniz yere taşıyabilir ve çift tıklayarak çalıştırabilirsiniz.
Program otomatik olarak root yetkisi isteyecektir (şifre soracaktır).

```bash
./dist/usb_namer
```

### Başkalarıyla Paylaşma
Bu `usb_namer` dosyasını başka bir Linux kullanıcısına gönderdiğinizde, karşı tarafın **herhangi bir şey yüklemesine gerek yoktur**. 
Python, kütüphaneler vs. dosyanın içindedir.

**Gereksinimler:**
*   Standart bir Linux dağıtımı (Ubuntu, Debian, Fedora, vb.)
*   `udevadm` aracı (Linux'ta %99 yüklü gelir)
*   Masaüstü ortamı (Grafik arayüz için)


