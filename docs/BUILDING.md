# Building ClamMac

## Requirements

- macOS 11 or later to build the `.app` and `.dmg`
- Python 3.11 or later
- Xcode Command Line Tools (`xcode-select --install`) for `codesign`

The test suite, the linter and the icon generator run on any platform. Only the
application bundle needs macOS.

## Quick start

```sh
git clone https://github.com/tibcz/ClamMac.git
cd ClamMac
make venv       # create .venv and install dependencies
make check      # lint and test
make dmg        # build dist/ClamMac-<version>.dmg
```

`make help` lists everything.

## Running from source

```sh
make run
# or
source .venv/bin/activate
python3 -m clammac
```

Useful flags:

```sh
python3 -m clammac --verbose               # debug logging
python3 -m clammac --scan ~/Downloads      # open and scan immediately
python3 -m clammac --scheduled-scan quick  # headless, as launchd runs it
python3 -m clammac --update-definitions    # headless definition update
```

`CLAMMAC_HOME` relocates everything ClamMac writes, which is handy for trying a
clean first-run without disturbing a real install:

```sh
CLAMMAC_HOME=/tmp/clammac-test python3 -m clammac
```

## What the build does

`packaging/build_app.py` runs these in order:

1. **Generate the icon.** `packaging/make_icon.py` draws it from primitives and
   writes a multi-resolution `.icns`. No artwork files are stored in the repo.
2. **Run PyInstaller** against `packaging/ClamMac.spec`, which excludes the
   forty-odd Qt modules ClamMac never uses.
3. **Check `Info.plist`** for the keys the app depends on — in particular the
   privacy usage strings, without which macOS cannot even show the permission
   prompt and scans of protected folders silently read nothing.
4. **Sign**, innermost first. A signature covers everything nested inside it, so
   signing the bundle before its libraries would be immediately invalidated.
5. **Notarise**, if `NOTARY_PROFILE` is set.
6. **Start the built app** and check it reports its version — this catches a
   bundle that looks complete but cannot import its own extension modules.
7. **Build the disk image** with an `/Applications` symlink and a first-run note.

## Signing and notarising

Both optional, both driven by environment variables, neither stored in the repo:

```sh
export CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
export NOTARY_PROFILE="clammac-notary"
make dmg
```

To create the notarytool profile once:

```sh
xcrun notarytool store-credentials clammac-notary \
    --apple-id you@example.com \
    --team-id TEAMID \
    --password <app-specific-password>
```

Without `CODESIGN_IDENTITY` the bundle is signed ad hoc. It runs, but Gatekeeper
makes the user allow it explicitly on first launch. The DMG's "Read me first"
file and the release notes both explain that step.

## Universal binaries

A universal (Apple silicon + Intel) bundle needs a universal Python. The
runner-native Python on an Apple silicon machine is arm64-only, and PyInstaller
cannot invent the other half.

Use the python.org installer, which is genuinely universal2:

```sh
curl -fsSLO https://www.python.org/ftp/python/3.12.7/python-3.12.7-macos11.pkg
sudo installer -pkg python-3.12.7-macos11.pkg -target /
/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m venv .venv
```

`build_app.py` detects this and asks PyInstaller for a universal build; when the
interpreter is single-architecture it says so and names the architecture in the
DMG filename, so nobody ends up running the wrong download.

`.github/workflows/release.yml` does exactly this.

## Updating the pinned ClamAV engine

When ClamAV publishes a new release:

```sh
VERSION=1.5.5
curl -fLO "https://github.com/Cisco-Talos/clamav/releases/download/clamav-${VERSION}/clamav-${VERSION}.macos.universal.pkg"
shasum -a 256 "clamav-${VERSION}.macos.universal.pkg"
```

Add an entry to `clammac/resources/engine_manifest.json` with that digest and
the file's exact size, then:

```sh
python3 scripts/verify-manifest.py --version "$VERSION"
```

That downloads the package, confirms the digest and size, unpacks it with
ClamMac's own extractor, and confirms every Mach-O image still carries the
run-path ClamMac knows how to rewrite. If ClamAV ever changes how it builds its
macOS package, this is what tells you before a user finds out.

CI runs the same check on every push.

## Troubleshooting

**The built app will not start.** Run the executable directly to see why:

```sh
dist/ClamMac.app/Contents/MacOS/ClamMac --verbose
```

**"code object is not signed at all".** Something modified the bundle after
signing. Rebuild, or re-sign with `codesign --force --deep --sign - dist/ClamMac.app`.

**Scans find nothing in Desktop or Documents.** macOS denied access and the
prompt was never shown. Check the usage strings survived into `Info.plist`:

```sh
plutil -p dist/ClamMac.app/Contents/Info.plist | grep UsageDescription
```

**The bundle is enormous.** Check the Qt exclusions in `packaging/ClamMac.spec`
are still taking effect; a stray import of an excluded module pulls it back in.
