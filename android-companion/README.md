# BOLT12 Pay Android Companion

This is a deliberately small Android intent receiver, not a wallet. It registers for
`lightning:` links containing BOLT11 invoices or BOLT12 offers and for Amethyst's
BIP321 `bitcoin:?lno=...` handoff. It passes only a validated BOLT11/BOLT12 target to
the existing BOLT12 Pay web payment form. Bitcoin-only, Lightning Address, and LNURL
inputs are rejected.

The configured server must be the exact clean HTTPS origin where this version of the
BOLT12 Pay web app and its `/pay-intent` route are available. Payment data is placed in
a URL fragment and moved into same-tab `sessionStorage` by `/pay-intent`, so it is not
sent in HTTP requests or login redirect parameters. The web UI only pre-fills the
payment form; the user must still review and explicitly start every payment.

## Test from Android Studio

1. Open this `android-companion` directory as a project.
2. Run the `app` configuration on an emulator or Android device.
3. Enter the public HTTPS origin of the BOLT12 Pay server once.
4. Trigger a chooser with ADB, using non-payable test strings:

   ```text
   adb shell am start -a android.intent.action.VIEW -d 'lightning:lno1abcdef123'
   adb shell am start -a android.intent.action.VIEW -d 'lightning:lnbc10u1abcdef'
   adb shell am start -a android.intent.action.VIEW -d 'bitcoin:?lno=lno1abcdef123'
   ```

Select **BOLT12 Pay** in the Android chooser. The browser should open `/pay`, with the
target pre-filled and no payment started.
