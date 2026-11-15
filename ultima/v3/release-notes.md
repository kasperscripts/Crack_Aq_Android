Key alias relay update for Ultima iOS build10.

- Accepts `@Icon_Crack`, including mixed case, whitespace and invisible paste marks.
- Installs before the Ultima loader initializes and maps cached keys, native NSString factories and outgoing JSON values before encryption, as well as UIKit input reads.
- Preserves the supplied original license, server validation, expiration and device restrictions. This does not create an unlimited or offline license. The original license has not been independently verified on a physical iPhone.
- Keeps the original Ultima loader and game payload bytes unchanged. The main executable gains the companion dependency with matching library ordinal updates.
- Includes actual iOS simulator tests for input, cache, native string factories and outgoing JSON. Incoming responses and unrelated request fields remain unchanged.
- On failure, `IC3-Sxx-Myy` reports observed input paths and alias replacements; it does not indicate server acceptance.

Download the IPA below and sign the full app through ESign before installation. Enter `@Icon_Crack` again. No ZIP parts are required.
