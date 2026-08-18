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

// Provisioned identity (matched with vehicle's copy).
static const char BATTERY_ID[BATTLOCK_BAT_ID_LEN] = "BAT001";

// Full certificate programmed into the battery (see provisioning note).
static const BattLockCert battery_cert = {0};

// Nonce bytes received from the vehicle (must be signed exactly).
static uint8_t challenge_nonce[BATTLOCK_NONCE_LEN];
static bool has_challenge = false;

// ATECC608A key slot holding the battery's private key.
static const uint8_t KEY_SLOT = 0;

static uint32_t counter = 0;

// ---------------------------------------------------------------------
// Small helper: send a single CAN frame.
// ---------------------------------------------------------------------
static bool can_send(uint32_t id, const uint8_t *data, uint8_t len) {
    return can.sendMsgBuf(id, 0, len, (uint8_t *)data) == CAN_OK;
}

// ---------------------------------------------------------------------
// Fragmented payload sender.
// ---------------------------------------------------------------------
static bool send_payload(uint32_t id, const uint8_t *payload, uint16_t len) {
    uint8_t frame[CAN_DATA_LEN];
    uint16_t chunks = battlock_fragment_count(len);

    // Fragment 0: seq=0, total length (LE) in bytes 1..2, then 5 data bytes.
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

    // Fragments 1..n-1: 7 data bytes each; last sets the flag.
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
// Sign a 32-byte message with the ATECC608A private key (slot KEY_SLOT).
// Outputs 64 bytes: r || s.
// ---------------------------------------------------------------------
static bool sign_with_atecc(const uint8_t *message32, uint8_t *sig64) {
    return atecc.ecdsaSign(message32, sig64, KEY_SLOT);
}

// ---------------------------------------------------------------------
// Encode telemetry status. Classic CAN = 8 bytes, so the Python
// "IfffBBB" status is split into two frames:
//   frame A (0x200): counter(uint32) | soc | soh | fault
//   frame B (0x201): voltage(f32) | current(f32) | temperature(f16)
// ---------------------------------------------------------------------
#define CAN_ID_BATTERY_STATUS_B 0x201

static bool send_status(void) {
    uint8_t a[CAN_DATA_LEN] = {0};
    uint32_t c = counter++;
    a[0] = (uint8_t)(c & 0xFF);
    a[1] = (uint8_t)((c >> 8) & 0xFF);
    a[2] = (uint8_t)((c >> 16) & 0xFF);
    a[3] = (uint8_t)((c >> 24) & 0xFF);
    a[4] = 85; // soc
    a[5] = 98; // soh
    a[6] = 0;  // fault_flags
    a[7] = 0;

    union { float f; uint8_t b[4]; } v, i;
    v.f = 51.2f;
    i.f = 12.4f;
    uint8_t b[CAN_DATA_LEN] = {0};
    b[0] = v.b[0]; b[1] = v.b[1]; b[2] = v.b[2]; b[3] = v.b[3];
    b[4] = i.b[0]; b[5] = i.b[1]; b[6] = i.b[2]; b[7] = i.b[3];

    if (!can_send(CAN_ID_BATTERY_STATUS, a, 8)) return false;
    return can_send(CAN_ID_BATTERY_STATUS_B, b, 8);
}

// ---------------------------------------------------------------------
void setup() {
    Serial.begin(115200);

    while (can.begin(CAN_BAUD) != CAN_OK) {
        delay(100);
    }
    Serial.println("BatteryNode: CAN ready");

    if (atecc.begin() == false) {
        Serial.println("BatteryNode: ATECC608A not found");
    } else {
        Serial.println("BatteryNode: ATECC608A ready");
    }

    state = STATE_DISCONNECTED;
}

void loop() {
    // 1) Advertise identity until auth request received.
    if (state == STATE_DISCONNECTED) {
        can_send(CAN_ID_AUTH_REQUEST, (const uint8_t *)BATTERY_ID, BATTLOCK_BAT_ID_LEN);
    }

    // 2) Receive frames.
    if (can.checkReceive()) {
        uint32_t id;
        uint8_t len = 0;
        uint8_t data[CAN_DATA_LEN] = {0};
        can.readMsgBuf(&id, &len, data);

        switch (id) {
            case CAN_ID_AUTH_REQUEST: {
                state = STATE_HELLO_RECEIVED;
                Serial.println("Battery: AUTH_REQUEST");
                // Send our certificate (fragmented).
                uint8_t raw[BATTLOCK_CERT_LEN];
                memcpy(raw, &battery_cert, sizeof(battery_cert));
                send_payload(CAN_ID_CERTIFICATE, raw, sizeof(raw));
                break;
            }

            case CAN_ID_NONCE: {
                // Reassemble the 32-byte nonce.
                static BattLockReassembly reass;
                if (battlock_reassembly_feed(&reass, data, len)) {
                    if (reass.len == BATTLOCK_NONCE_LEN) {
                        memcpy(challenge_nonce, reass.buffer, BATTLOCK_NONCE_LEN);
                        has_challenge = true;
                        state = STATE_CHALLENGE_SENT;
                        Serial.println("Battery: NONCE received");
                    }
                    battlock_reassembly_init(&reass);
                }
                break;
            }

            case CAN_ID_AUTH_RESULT: {
                if (data[0] == 0x01) {
                    state = STATE_AUTHENTICATED;
                    Serial.println("Battery: auth OK");
                } else {
                    state = STATE_DISCONNECTED;
                    Serial.println("Battery: auth FAILED");
                }
                break;
            }

            case CAN_ID_SESSION_ID: {
                state = STATE_ACTIVE_SESSION;
                Serial.println("Battery: session established");
                break;
            }

            default:
                break;
        }
    }

    // 3) Sign the challenge once received.
    if (has_challenge && state == STATE_CHALLENGE_SENT) {
        uint8_t sig[BATTLOCK_SIG_LEN];
        if (sign_with_atecc(challenge_nonce, sig)) {
            send_payload(CAN_ID_SIGNATURE, sig, sizeof(sig));
            has_challenge = false;
            Serial.println("Battery: signature sent");
        }
    }

    // 4) Stream telemetry in an active session.
    if (state == STATE_ACTIVE_SESSION) {
        send_status();
    }

    delay(50);
}
