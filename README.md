A skeleton for an F-Droid repo setup using a YubiHSM 2 for signing

## Requirements

    sudo apt install fdroidserver python3-yaml python3-cryptography apksigner
    sudo apt install python3-yubihsm yubihsm-pkcs11 python3-usb
    sudo apt install yubihsm-shell yubihsm-connector opensc

## How to sign

1. Ensure all APK files for all apps are in the `repo/` folder
2. Run `./scripts/sign.sh` to sign the repo
3. Upload the `repo/` folder to your F-Droid webserver

## Adding app updates

Just drop the new APK files into the `repo/` folder and run `./scripts/sign.sh` again.
Due to bugs in fdroidserver, you may need to give the new APK file a different name than the old one.
Old APKs from the same app could be removed from the `repo/` folder, but it is not required.

## Adding a new app

When adding a new app to the `repo/` folder, you will see a warning such as:

    WARNING: com.example.apk (com.example) has no metadata!

You can either run `fdroid update -c` or manually generate the metadata file in `repo/metadata/com.example.yml`.
