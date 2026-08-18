/*
 * BattLock ATECC608B serial bridge (runs on the BATTERY ESP32, COM3).
 *
 * Lets the laptop's Python crypto API drive the real secure element over
 * USB serial. This is a provisioning/test tool — NOT vehicle.ino /
 * battery.ino — so it stays in the Crypto/Security Lead's lane.
 *
 * Protocol (ASCII, one command per line, 115200 baud):
 *   PING                                  -> PONG
 *   SIGN <64-hex-chars>                   -> SIG:<128 hex> (raw R||S, 64 B)
 *   PUBKEY                                -> PUB:<128 hex> (64 B)
 *   GENKEY                                -> OK (creates new keypair in slot 0)
 *   VERIFY <64-hex msg> <128-hex sig> <128-hex pub>
 *                                           -> VERIFY:1 or VERIFY:0
 *
 * Uses the SparkFun ATECCX08a Arduino library against an ATECC608B on
 * address 0x60, I2C on SDA=21 / SCL=22.
 */

#include <Wire.h>
#include <SparkFun_ATECCX08a_Arduino_Library.h>

#define ATECC_I2C_ADDR 0x60
#define KEY_SLOT 0x0000

ATECCX08A atecc;

static uint8_t hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0xFF;
}

static bool hexToBytes(const String &hex, uint8_t *out, size_t outLen) {
    if (hex.length() != outLen * 2) return false;
    for (size_t i = 0; i < outLen; i++) {
        uint8_t hi = hexNibble(hex[2 * i]);
        uint8_t lo = hexNibble(hex[2 * i + 1]);
        if (hi == 0xFF || lo == 0xFF) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static void printHex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 0x10) Serial.print('0');
        Serial.print(data[i], HEX);
    }
}

static void sendError(const char *msg) {
    Serial.print("ERR:");
    Serial.println(msg);
}

void setup() {
    Serial.begin(115200);
    while (!Serial) { ; }

    Wire.begin(21, 22);

    if (!atecc.begin(ATECC_I2C_ADDR, Wire, Serial)) {
        sendError("ATECC608B not detected on I2C");
    }
}

static void handleSign(const String &hexMsg) {
    uint8_t msg[32];
    if (!hexToBytes(hexMsg, msg, 32)) {
        sendError("SIGN needs 64 hex chars (32-byte message)");
        return;
    }
    if (!atecc.createSignature(msg, KEY_SLOT)) {
        sendError("createSignature failed");
        return;
    }
    Serial.print("SIG:");
    printHex(atecc.signature, SIGNATURE_SIZE);
    Serial.println();
}

static void handlePubKey() {
    if (!atecc.generatePublicKey(KEY_SLOT)) {
        sendError("generatePublicKey failed");
        return;
    }
    Serial.print("PUB:");
    printHex(atecc.publicKey64Bytes, PUBLIC_KEY_SIZE);
    Serial.println();
}

static void handleGenKey() {
    if (!atecc.createNewKeyPair(KEY_SLOT)) {
        sendError("createNewKeyPair failed (slot 0 locked/config?)");
        return;
    }
    Serial.println("OK");
}

static void handleVerify(const String &args) {
    int sp1 = args.indexOf(' ');
    int sp2 = args.indexOf(' ', sp1 + 1);
    if (sp1 < 0 || sp2 < 0) {
        sendError("VERIFY needs: <msg64hex> <sig128hex> <pub128hex>");
        return;
    }
    String msgHex = args.substring(0, sp1);
    String sigHex = args.substring(sp1 + 1, sp2);
    String pubHex = args.substring(sp2 + 1);

    uint8_t msg[32], sig[64], pub[64];
    if (!hexToBytes(msgHex, msg, 32) ||
        !hexToBytes(sigHex, sig, 64) ||
        !hexToBytes(pubHex, pub, 64)) {
        sendError("bad hex lengths");
        return;
    }
    bool ok = atecc.verifySignature(msg, sig, pub);
    Serial.print("VERIFY:");
    Serial.println(ok ? 1 : 0);
}

void loop() {
    if (!Serial.available()) return;

    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) return;

    int sp = line.indexOf(' ');
    String cmd = (sp < 0) ? line : line.substring(0, sp);
    String args = (sp < 0) ? "" : line.substring(sp + 1);

    if (cmd == "PING") {
        Serial.println("PONG");
    } else if (cmd == "SIGN") {
        handleSign(args);
    } else if (cmd == "PUBKEY") {
        handlePubKey();
    } else if (cmd == "GENKEY") {
        handleGenKey();
    } else if (cmd == "VERIFY") {
        handleVerify(args);
    } else {
        sendError("unknown command");
    }
}
