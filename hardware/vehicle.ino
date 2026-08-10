#include <SPI.h>
#include <mcp_can.h>
#include <Wire.h>
#include <AES.h>
#include <SHA256.h>
#include <ATECC608A.h>
#include <cstring>

#include "battlock_protocol.h"

// ---------------------------------------------------------------------
// ESP32 + MCP2515 wiring (change to match the hardware team's board)
// ---------------------------------------------------------------------
#define CAN_CS_PIN   5      // MCP2515 CS
#define CAN_INT_PIN  4      // MCP2515 INT
#define CAN_BAUD     CAN_500KBPS

#define ATECC_I2C_ADDR 0x60 // default ATECC608A I2C address

MCP_CAN can(CAN_CS_PIN);
ATECC608A atecc(ATECC608A::SDA, ATECC608A::SCL, ATECC608A::ADDR0);

static BattLockState state = STATE_DISCONNECTED;

// Manufacturer root CA public key used to verify battery certificates.
// This is a placeholder (65 bytes: 0x04 || X || Y) - see provisioning.
static const uint8_t root_ca_public_key[65] = {0};

// ATECC608A key slot holding the manufacturer's public key for cert
// verification, and a slot for the session verification.
static const uint8_t VERIFY_SLOT = 0;

// Reassembled pieces.
static uint8_t cert_raw[BATTLOCK_CERT_LEN];
static uint8_t sig_raw[BATTLOCK_SIG_LEN];

// Replay protection (mirrors crypto/counters/replay_protection.py).
static uint32_t last_counter = 0;

// Session.
static uint8_t session_active = false;

// ---------------------------------------------------------------------
// CAN helpers.
// ---------------------------------------------------------------------
static bool can_send(uint32_t id, const uint8_t *data, uint8_t len) {
    return can.sendMsgBuf(id, 0, len, (uint8_t *)data) == CAN_OK;
}

static bool send_payload(uint32_t id, const uint8_t *payload, uint16_t len) {
    uint8_t frame[CAN_DATA_LEN];
    uint16_t chunks = battlock_fragment_count(len);

    frame[0] = 0x00;
    frame[1] = (uint8_t)(len & 0xFF);
    frame[2] = (uint8_t)((len >> 8) & 0xFF);
    for (uint8_t j = 0; j < FRAG_FIRST_DATA; j++) {
        frame[FRAG_HEAD_BYTES + j] = (j < len) ? payload[j] : 0;
    }
    if (chunks == 1) {
        frame[0] = FRAG_LAST_FLAG;
        if (!can_send(id, frame, CAN_DATA_LEN)) return false;
        return true;
    }
    if (!can_send(id, frame, CAN_DATA_LEN)) return false;

    uint16_t off = FRAG_FIRST_DATA;
    for (uint16_t i = 1; i < chunks; i++) {
        bool last = (i == chunks - 1);
        frame[0] = (uint8_t)((last ? FRAG_LAST_FLAG : 0) | i);
        for (uint8_t j = 0; j < FRAG_DATA_BYTES; j++) {
            frame[1 + j] = (off + j < len) ? payload[off + j] : 0;
        }
        if (!can_send(id, frame, CAN_DATA_LEN)) return false;
        off += FRAG_DATA_BYTES;
    }
    return true;
}

// ---------------------------------------------------------------------
// Verify a 64-byte ECDSA signature over a 32-byte message using the
// ATECC608A (public key in VERIFY_SLOT or supplied).
// ---------------------------------------------------------------------
static bool verify_with_atecc(const uint8_t *message32,
                              const uint8_t *sig64,
                              const uint8_t *pubkey65,
                              uint8_t slot) {
    if (pubkey65 != NULL) {
        return atecc.ecdsaVerify(message32, sig64, pubkey65);
    }
    return atecc.ecdsaVerify(message32, sig64, slot);
}

// ---------------------------------------------------------------------
// Certificate verification: recompute the manufacturer signature over
// the cert fields and check with the root CA key.
// (Same construction as crypto/certs/certificate.py)
// ---------------------------------------------------------------------
static bool verify_certificate(const BattLockCert *cert) {
    // Build the exact byte string the manufacturer signed.
    // Order must match crypto/certs/certificate.py:
    // battery_id || manufacturer_id || public_key || issue || expiry
    uint8_t msg[6 + 8 + 65 + 3 + 3];
    uint16_t o = 0;
    memcpy(msg + o, cert->battery_id, BATTLOCK_BAT_ID_LEN); o += 6;
    memcpy(msg + o, cert->manufacturer_id, 8); o += 8;
    memcpy(msg + o, cert->public_key, 65); o += 65;
    msg[o++] = cert->issue_year;
    msg[o++] = cert->issue_month;
    msg[o++] = cert->issue_day;
    msg[o++] = cert->expiry_year;
    msg[o++] = cert->expiry_month;
    msg[o++] = cert->expiry_day;

    // ATECC608A needs a 32-byte digest.
    SHA256 sha;
    sha.update(msg, o);
    uint8_t digest[32];
    sha.finalize(digest, 32);

    return verify_with_atecc(digest, cert->signature, root_ca_public_key, VERIFY_SLOT);
}

// ---------------------------------------------------------------------
// Telemetry reception with replay + injection checks.
// Frame A: counter + soc/soh/fault. Frame B: floats.
// ---------------------------------------------------------------------
#define CAN_ID_BATTERY_STATUS_B 0x201

static uint32_t pending_counter = 0;
static uint8_t  pending_flags[4] = {0};
static bool     have_frame_a = false;

static void handle_status_a(const uint8_t *data) {
    pending_counter = (uint32_t)data[0]
                    | ((uint32_t)data[1] << 8)
                    | ((uint32_t)data[2] << 16)
                    | ((uint32_t)data[3] << 24);
    pending_flags[0] = data[4]; // soc
    pending_flags[1] = data[5]; // soh
    pending_flags[2] = data[6]; // fault
    have_frame_a = true;
}

static void handle_status_b(const uint8_t *data) {
    union { float f; uint8_t b[4]; } v, i;
    v.b[0] = data[0]; v.b[1] = data[1]; v.b[2] = data[2]; v.b[3] = data[3];
    i.b[0] = data[4]; i.b[1] = data[5]; i.b[2] = data[6]; i.b[3] = data[7];

    // Injection check (mirrors can/simulation/vehicle_node.py).
    if (v.f > 100.0f || i.f > 500.0f) {
        Serial.println("Vehicle: INJECTION ATTACK DETECTED");
        return;
    }
    // Replay check (mirrors crypto/counters/replay_protection.py).
    if (pending_counter <= last_counter) {
        Serial.println("Vehicle: REPLAY ATTACK DETECTED");
        return;
    }
    last_counter = pending_counter;
    Serial.print("Vehicle: VALID status counter=");
    Serial.println((unsigned long)pending_counter);
}

// ---------------------------------------------------------------------
void setup() {
    Serial.begin(115200);

    while (can.begin(CAN_BAUD) != CAN_OK) {
        delay(100);
    }
    Serial.println("VehicleNode: CAN ready");

    if (atecc.begin() == false) {
        Serial.println("VehicleNode: ATECC608A not found");
    } else {
        Serial.println("VehicleNode: ATECC608A ready");
    }

    state = STATE_DISCONNECTED;
}

void loop() {
    if (!can.checkReceive()) {
        delay(10);
        return;
    }

    uint32_t id;
    uint8_t len = 0;
    uint8_t data[CAN_DATA_LEN] = {0};
    can.readMsgBuf(&id, &len, data);

    // Telemetry frames in active session.
    if (state == STATE_ACTIVE_SESSION) {
        if (id == CAN_ID_BATTERY_STATUS) {
            handle_status_a(data);
            return;
        }
        if (id == CAN_ID_BATTERY_STATUS_B) {
            if (have_frame_a) {
                handle_status_b(data);
                have_frame_a = false;
            }
            return;
        }
    }

    switch (id) {
        case CAN_ID_AUTH_REQUEST: {
            state = STATE_HELLO_RECEIVED;
            Serial.println("Vehicle: identity received");
            break;
        }

        case CAN_ID_CERTIFICATE: {
            static BattLockReassembly reass;
            if (battlock_reassembly_feed(&reass, data, len)) {
                if (reass.len == BATTLOCK_CERT_LEN) {
                    memcpy(cert_raw, reass.buffer, BATTLOCK_CERT_LEN);
                    BattLockCert *cert = (BattLockCert *)cert_raw;
                    if (verify_certificate(cert)) {
                        state = STATE_CERT_VERIFIED;
                        Serial.println("Vehicle: certificate verified");
                        // Send 32-byte nonce challenge.
                        static uint8_t nonce[BATTLOCK_NONCE_LEN];
                        // Provision a fresh nonce here (placeholder).
                        for (int i = 0; i < 32; i++) nonce[i] = (uint8_t)(millis() >> (i % 16));
                        send_payload(CAN_ID_NONCE, nonce, BATTLOCK_NONCE_LEN);
                        state = STATE_CHALLENGE_SENT;
                        Serial.println("Vehicle: challenge sent");
                    } else {
                        state = STATE_DISCONNECTED;
                        Serial.println("Vehicle: certificate REJECTED");
                    }
                }
                battlock_reassembly_init(&reass);
            }
            break;
        }

        case CAN_ID_SIGNATURE: {
            static BattLockReassembly reass;
            if (battlock_reassembly_feed(&reass, data, len)) {
                if (reass.len == BATTLOCK_SIG_LEN) {
                    memcpy(sig_raw, reass.buffer, BATTLOCK_SIG_LEN);
                    // The battery signs the nonce; verify with the
                    // certificate's public key.
                    BattLockCert *cert = (BattLockCert *)cert_raw;
                    if (verify_with_atecc(reass.buffer /*digest placeholder*/,
                                          sig_raw, cert->public_key, VERIFY_SLOT)) {
                        state = STATE_AUTHENTICATED;
                        uint8_t ok = 1;
                        can_send(CAN_ID_AUTH_RESULT, &ok, 1);
                        Serial.println("Vehicle: signature verified");
                        // Session ID frame.
                        uint8_t sid[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04};
                        can_send(CAN_ID_SESSION_ID, sid, 8);
                        state = STATE_ACTIVE_SESSION;
                        last_counter = 0;
                        Serial.println("Vehicle: ACTIVE_SESSION");
                    } else {
                        state = STATE_DISCONNECTED;
                        uint8_t fail = 0;
                        can_send(CAN_ID_AUTH_RESULT, &fail, 1);
                        Serial.println("Vehicle: signature REJECTED");
                    }
                }
                battlock_reassembly_init(&reass);
            }
            break;
        }

        default:
            break;
    }

    delay(10);
}
