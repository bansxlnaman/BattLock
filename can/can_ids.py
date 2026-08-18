# BattLock CAN Protocol — Identifier Table
# Person 3 (CAN Protocol / Software): single source of truth for all CAN IDs.
#
# NOTE ON COMPATIBILITY:
# BATTERY_STATUS (0x200) is retained as a backward-compatible alias for
# BATTERY_STATUS_A. This lets the existing encoder/decoder/simulation keep
# running unchanged while the status frame is migrated to the A/B/C split.
# New code should use BATTERY_STATUS_A / _B / _C.

# --- Authentication / session control frames ---
AUTH_REQUEST = 0x100
NONCE        = 0x101
SIGNATURE    = 0x102
AUTH_RESULT  = 0x103
CERTIFICATE  = 0x104
SESSION_ID   = 0x105

# --- Battery status frames (split so each fits the Classic CAN 8-byte limit) ---
BATTERY_STATUS_A = 0x200   # counter, soc, soh, fault_flags
BATTERY_STATUS_B = 0x201   # voltage, current
BATTERY_STATUS_C = 0x202   # temperature

# Backward-compatible alias: the old single-frame status ID == STATUS_A.
BATTERY_STATUS = BATTERY_STATUS_A

# --- Classic CAN constraint ---
CAN_MAX_DATA = 8

# --- Fault flag bitmask (unchanged) ---
OVERVOLTAGE  = 0x0001
UNDERVOLTAGE = 0x0002
OVERCURRENT  = 0x0004
OVERTEMP     = 0x0008
COMM_ERROR   = 0x0010
AUTH_FAILURE = 0x0020
