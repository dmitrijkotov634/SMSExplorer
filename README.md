# SMS Explorer

### Browse the Web over SMS

Simple SMS-based web browser inspired
by [TxtNet Browser](https://github.com/lukeaschenbrenner/TxtNet-Browser). Uses Termux API as server backend
with simple Material3 design.

## How it works

Send URL via SMS → Server fetches page → Content compressed with Brotli → Encoded with Base-114 → Sent back
via SMS

## Key Differences from TxtNet Browser

- **Termux API Server**: No Shizuku or complex permissions required
- **Minimal Code**: Focused on core functionality
- **Stable SMS Handling**: Uses Termux's native SMS API
- **Simple Material3 Design**: Clean and modern interface

## Requirements

- Android device with Termux + Termux:API
- Python with required libraries
- SMS capability
- **Unlimited SMS plan recommended** for both server and client

⚠️ **All traffic transmitted in plaintext over SMS**

Based on TxtNet Browser by lukeaschenbrenner.

