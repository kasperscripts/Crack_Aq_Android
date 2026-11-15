Umbrella iOS with the existing local key check renamed to `@Icon_Crack`.

The original check removes `@` and underscores before comparing the key. Its comparison constant now matches the normalized new key. The original ARM64 activation and normalization routines were executed in nine before/after scenarios, including rejection of wrong keys.

The app display name, activation messages and Telegram reference use `@Icon_Crack` and https://t.me/Icon_Crack. No new runtime framework, network hook or input hook is added. Original game payloads, native loader sections and the supplied capability/session/runtime data are preserved.

The IPA uses standard ZIP32 packaging and all entries pass CRC verification. Sign the full IPA in ESign before installation. Physical iPhone operation has not been tested here.
