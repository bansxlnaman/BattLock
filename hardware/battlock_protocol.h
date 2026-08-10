#ifndef BATTLOCK_PROTOCOL_H
#define BATTLOCK_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

// ---------------------------------------------------------------------
// CAN message IDs (mirrors can/can_ids.py)
// ---------------------------------------------------------------------
#define CAN_ID_AUTH_REQUEST   0x100
#define CAN_ID_NONCE          0x101
#define CAN_ID_SIGNATURE      0x102
#define CAN_ID_AUTH_RESULT    0x103
#define CAN_ID_CERTIFICATE    0x104
#define CAN_ID_SESSION_ID     0x105
#define CAN_ID_BATTERY_STATUS 0x200

// ---------------------------------------------------------------------
// Fixed fields
// ---------------------------------------------------------------------
#define BATTLOCK_NONCE_LEN    32          // challenge nonce (bytes)
#define BATTLOCK_SIG_LEN      64          // ECDSA P-256 r||s (bytes)
#define BATTLOCK_CERT_LEN     148         // packed certificate (bytes)
#define CAN_DATA_LEN          8           // classic CAN payload
#define BATTLOCK_BAT_ID_LEN   7           // "BAT001\0"

// ---------------------------------------------------------------------
// Connection states (mirrors protocol/state_machine.py)
// ---------------------------------------------------------------------
typedef enum {
    STATE_DISCONNECTED = 0,
    STATE_HELLO_RECEIVED = 1,
    STATE_CERT_VERIFIED = 2,
    STATE_CHALLENGE_SENT = 3,
    STATE_AUTHENTICATED = 4,
    STATE_ACTIVE_SESSION = 5
} BattLockState;

// ---------------------------------------------------------------------
// Packed battery certificate (148 bytes).
// Fits in 19 CAN frames (fragmented).
// ---------------------------------------------------------------------
typedef struct {
    uint8_t  battery_id[BATTLOCK_BAT_ID_LEN];   // 6
    uint8_t  manufacturer_id[8];                 // 8
    uint8_t  issue_year;                         // 1
    uint8_t  issue_month;                        // 1
    uint8_t  issue_day;                          // 1
    uint8_t  expiry_year;                        // 1
    uint8_t  expiry_month;                       // 1
    uint8_t  expiry_day;                         // 1
    uint8_t  public_key[65];                     // 65 (0x04 || X || Y)
    uint8_t  signature[64];                      // 64 (manufacturer sig)
} BattLockCert;

// ---------------------------------------------------------------------
// Battery status frame (mirrors can/encoder.py encode_status: IfffBBB)
// PACKED layout in the 8-byte CAN payload:
//   [0..3] counter   uint32 LE
//   [4..7] voltage   float  LE
//   [8..11] current  float  LE   <- does NOT fit 8-byte frame.
//   ...
// Classic CAN is 8 bytes, so the status is split across two frames
// (see below). Frame A: counter + flags. Frame B: floats.
// ---------------------------------------------------------------------
typedef struct {
    uint32_t counter;
    float    voltage;
    float    current;
    float    temperature;
    uint8_t  soc;
    uint8_t  soh;
    uint8_t  fault_flags;
} BattLockStatus;

// ---------------------------------------------------------------------
// Fragmentation transport for multi-frame payloads.
//
// CAN carries 8 bytes/frame. Large payloads (nonce, signature,
// certificate) are split. Layout:
//   - Fragment 0: byte[0]=0x00, bytes[1..2]=total payload length (LE),
//                 bytes[3..7]=first 5 payload bytes.
//   - Fragments 1..n-1: byte[0]=sequence index, bytes[1..7]=7 payload
//                 bytes. The last fragment sets FRAG_LAST_FLAG on byte[0].
// The receiver therefore knows the exact total length up front.
// ---------------------------------------------------------------------
#define FRAG_LAST_FLAG 0x80
#define FRAG_HEAD_BYTES 3   // byte0 (seq) + 2 length bytes
#define FRAG_FIRST_DATA 5   // payload bytes in fragment 0
#define FRAG_DATA_BYTES 7   // payload bytes in fragments 1..n-1

// Max bytes a payload transport can carry (arbitrary, certificates ~148)
#define TRANSPORT_MAX 512

typedef struct {
    uint8_t buffer[TRANSPORT_MAX];
    uint16_t len;
    uint16_t total;
    bool complete;
} BattLockReassembly;

// Initialize a reassembly buffer.
static inline void battlock_reassembly_init(BattLockReassembly *r) {
    r->len = 0;
    r->total = 0;
    r->complete = false;
}

// Feed one received CAN frame into the reassembly.
// Returns true when the payload is complete.
static inline bool battlock_reassembly_feed(BattLockReassembly *r,
                                            const uint8_t *data, uint8_t dlc) {
    uint8_t seq = data[0] & ~FRAG_LAST_FLAG;

    if (seq == 0) {
        // First fragment: read total length from bytes 1..2 (little-endian).
        r->len = 0;
        r->total = (uint16_t)data[1] | ((uint16_t)data[2] << 8);
        r->complete = false;
        uint8_t chunk = FRAG_FIRST_DATA;
        if (chunk > r->total) chunk = (uint8_t)r->total;
        if (r->len + chunk <= TRANSPORT_MAX) {
            for (uint8_t j = 0; j < chunk; j++) {
                r->buffer[r->len + j] = data[FRAG_HEAD_BYTES + j];
            }
            r->len += chunk;
        }
    } else {
        uint8_t chunk = (dlc > 1) ? (dlc - 1) : 0;
        if (chunk > FRAG_DATA_BYTES) chunk = FRAG_DATA_BYTES;
        if (r->len + chunk > r->total) chunk = (uint8_t)(r->total - r->len);
        if (r->len + chunk <= TRANSPORT_MAX) {
            for (uint8_t j = 0; j < chunk; j++) {
                r->buffer[r->len + j] = data[1 + j];
            }
            r->len += chunk;
        }
    }

    if ((data[0] & FRAG_LAST_FLAG) != 0) {
        r->complete = true;
        return true;
    }
    return false;
}

// Number of fragment frames needed for a given payload length.
static inline uint16_t battlock_fragment_count(uint16_t len) {
    if (len <= FRAG_FIRST_DATA) return 1;
    return 1 + (len - FRAG_FIRST_DATA + FRAG_DATA_BYTES - 1) / FRAG_DATA_BYTES;
}

#endif // BATTLOCK_PROTOCOL_H
