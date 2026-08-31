# Replacing the Qt libraries in ClamMac

ClamMac uses **PySide6** and **Qt** under the **LGPL-3.0**. Section 4(d) of that
licence requires that you be able to replace those libraries with your own
version and still run the application. This document is how.

Nothing here is needed to *use* ClamMac. It exists so the LGPL obligation is met
in a way you can actually follow.

## What is shipped, and how

ClamMac links Qt **dynamically** and ships it **unmodified**. Inside
`ClamMac.app` you will find:

```
ClamMac.app/Contents/
├── MacOS/ClamMac                     the launcher
└── Frameworks/
    ├── PySide6/                      the Python bindings
    ├── QtCore.framework/             Qt itself, one framework per module
    ├── QtGui.framework/
    ├── QtWidgets.framework/
    └── ...
```

No Qt source was patched. The libraries are exactly what `pip install PySide6`
produced, relocated into the bundle by PyInstaller.

## Replacing them in an existing build

1. Build or obtain the Qt and PySide6 version you want. It must be
   binary-compatible — the same major version (Qt 6) and an ABI-compatible
   minor version. Check what is currently there:

   ```sh
   /Applications/ClamMac.app/Contents/MacOS/ClamMac --version
   python3 -c "import PySide6; print(PySide6.__version__)"
   ```

2. Replace the frameworks in place:

   ```sh
   cd /Applications/ClamMac.app/Contents/Frameworks
   rm -rf QtCore.framework QtGui.framework QtWidgets.framework
   cp -R /path/to/your/Qt/lib/QtCore.framework .
   cp -R /path/to/your/Qt/lib/QtGui.framework .
   cp -R /path/to/your/Qt/lib/QtWidgets.framework .
   ```

3. Fix the install names so the bundle finds them where they now live:

   ```sh
   install_name_tool -id "@rpath/QtCore.framework/Versions/A/QtCore" \
       QtCore.framework/Versions/A/QtCore
   ```

   Repeat for each framework you replaced. `otool -L` shows what a binary
   currently expects.

4. Re-sign. Modifying a signed bundle invalidates its signature, and on Apple
   silicon an invalid signature means the app will not start at all:

   ```sh
   codesign --force --deep --sign - /Applications/ClamMac.app
   ```

   An ad-hoc signature (`-`) is enough to run it locally. Use your own
   Developer ID if you intend to distribute the result.

5. Run it. If it does not start, `Console.app` and

   ```sh
   /Applications/ClamMac.app/Contents/MacOS/ClamMac --verbose
   ```

   will say why — usually a version mismatch or a missing install-name fix.

## Building against your own Qt from source

Often simpler than surgery on a finished bundle:

```sh
git clone https://github.com/tibcz/ClamMac.git
cd ClamMac
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip wheel

# install your PySide6 build instead of the one on PyPI
pip install /path/to/your/PySide6-*.whl

pip install pyinstaller pytest ruff
python3 packaging/build_app.py
```

The result in `dist/` is built against whatever PySide6 is in the environment.

## Getting the corresponding source

- **Qt** — <https://download.qt.io/official_releases/qt/> (also
  <https://code.qt.io/cgit/qt/qt5.git/>)
- **PySide6** — <https://download.qt.io/official_releases/QtForPython/> (also
  <https://code.qt.io/cgit/pyside/pyside-setup.git/>)
- **ClamMac** — <https://github.com/tibcz/ClamMac>

The Qt version a given ClamMac release was built against is recorded in that
release's notes, and `requirements.txt` records the constraint.

## If you get stuck

Open an issue at <https://github.com/tibcz/ClamMac/issues>. Failing to relink
is a bug in these instructions, not a fact of life, and it will be fixed.
