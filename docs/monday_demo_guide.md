# BattLock — Monday Demo Plan

Updated plan for the Monday evaluation. Everything here is tested and working
on the demo machine. Goal: prove the Simulink model and our real Python
security code work together to verify the BattLock system.

---

## PART 1 — The 60-second pitch

> BattLock protects EV battery-to-vehicle communication over CAN. Only
> authentic, manufacturer-certified batteries may talk to the vehicle. Our
> demo proves it works through a **co-simulation**: the Simulink model
> simulates the CAN bus and generates the frames, and the real BattLock
> Python code verifies those frames. We run six attack scenarios — including
> replay, signature forgery, voltage injection, and a combined attack — and
> the two independent implementations agree on every verdict.

Key line to repeat: **"Simulink simulates the bus. Our real code makes the
security decisions."**

---

## PART 2 — What the evaluator will see

| # | Demo step | What it shows |
|---|-----------|---------------|
| 1 | `run_integration` (one command) | Full pipeline: Simulink exports CAN frames → Python verifies → plot + report generated |
| 2 | Console agreement table | Python and Simulink agree on all 6 attack modes (every row YES) |
| 3 | `integration_plot.png` | 2-row figure: top = Python verdicts, bottom = Simulink verdicts — identical rows = agreement |
| 4 | `python run_battlock.py` | The real ECDSA auth flow ending in ACTIVE_SESSION + metrics |

---

## PART 3 — Setup checklist (BEFORE Monday)

### Software on the demo machine
- [ ] MATLAB R2025a (with Simulink + Stateflow)
- [ ] Python 3.11
- [ ] `pip install cryptography psutil` in Python 3.11

### Files
- `<repo>/simulink/` — model + MATLAB scripts
- `<repo>/integration/` — Python verifier (`verify_frames.py`)

### The model
- File: `<repo>/simulink/Battlock_System2.slx`
- Renamed from `Battlock_System-2.slx` (MATLAB model names can't contain `-`)
- Signal logging already enabled on all outputs — nothing to configure

---

## PART 4 — DEMO ROUTE 1: One-command co-simulation (RECOMMENDED)

The main demo. No Simulink knowledge required.

### Steps (~5 minutes)

1. Open MATLAB (just the app — the script drives Simulink).
2. At the MATLAB command window:
   ```
   cd C:\...\BattLock\simulink
   ```
   (Use the real path on the machine.)
3. Run:
   ```
   run_integration
   ```
4. Watch the three phases print:
   ```
   [1/3] Exporting CAN frames from Simulink...
   [2/3] Verifying frames with real BattLock Python code...
   [3/3] Generating integration plot and report...
   ```
5. When finished, show:
   - `integration_report.csv` — the agreement table (every mode = YES)
   - `integration_plot.png` — the 2-row verdict figure

### The agreement table (memorize this)

```
mode  attack                      py_auth  mdl_auth  agree
0     No attack                     1        1       YES   <- normal battery works
1     Replay                        1        1       YES   <- replay detected
2     Signature spoof               0        0       YES   <- forged signature rejected
3     Voltage injection             1        1       YES   <- injected voltage detected
4     Signature drop                0        0       YES   <- dropped signature rejected
5     Spoof + voltage injection     0        0       YES   <- both caught at once
```

- `py_*` = verdict from **our Python code**
- `mdl_*` = verdict from the **Simulink model** (independent)
- They match → the model faithfully represents our real system
- Telemetry is blocked for EVERY attack mode — only the normal baseline
  streams SOC. Replay and injection raise the flag AND stop telemetry.

### The plot (2 rows, 6 columns)

- **Top row**: Python verdicts (auth blue / replay red / injection magenta / SOC green)
- **Bottom row**: Simulink verdicts (same colors)
- Each column is one attack mode
- Say: *"Top row is our real code deciding on the frames. Bottom row is
  Simulink's own verdict. They trace identically — that's the agreement."*
- Rule: blue up = auth accepted, red up = replay, magenta up = injection,
  green up = telemetry flowing. SOC is scaled (/85) to fit the 0–1 axis.

---

## PART 5 — DEMO ROUTE 2: Show the real Python security stack

Run in the terminal from `<repo>`:

```
python run_battlock.py
```

You'll see the full authentication flow:

```
Root CA Ready
Battery Public Key Generated
Certificate Generated
CAN Network Online
...Vehicle → Battery / Battery → Vehicle...
[STATE] session_established → ACTIVE_SESSION
BATTERY AUTHENTICATED / SECURE SESSION ACTIVE
Total Execution Time / Total CAN Messages / Total Bytes / Average Latency
```

This shows the **real cryptography**: ECDSA P-256 keypairs, certificates,
challenge–response handshake, session creation, replay protection.

Why show both? Route 1 proves the model matches our code; Route 2 proves the
code does real crypto.

---

## PART 6 — DEMO ROUTE 3 (optional): Attack mode deep-dive

Inside the model:

1. Open `Battlock_System2.slx` (double-click, or `open_system('Battlock_System2')`).
2. Double-click the **Attack_Module** subsystem.
3. Find the block **Constant5** (value `0`). Double-click it.
4. Change the **Constant value** to one of these, then press OK:
   - `1` → replay attack (stale counter) → `replay_detected` lights up
   - `2` → signature spoofing → auth blocked, no telemetry
   - `3` → voltage injection (999 V) → `injection_detected` lights up
   - `4` → signature dropping → auth blocked
   - `5` → spoof + voltage injection → auth blocked AND `injection_detected`
5. Press **Run** (green play button). Let it run 10 s.
6. Open the **Dashboard** subsystem and watch the displays/scopes.

IMPORTANT: set the value back to `0` when done, or save the model.

---

## PART 7 — If asked "which code ran and where is the output?"

> "MATLAB ran the Simulink model through `export_frames.m`, which produced
> the frames in `frames.csv` — the model's own verdicts are the `model_*`
> columns. Then Python's `verify_frames.py` read that file and made its own
> decisions using our real code, adding the `py_*` columns. The plot reads
> `frames_verified.csv`: top row is Python, bottom row is Simulink."

Data flow to remember:

```
Simulink model  ── export_frames.m ──►  frames.csv (frame fields + model_* verdicts)
                                              │
                                              ▼
                       verify_frames.py  ──►  frames_verified.csv (+ py_* verdicts)
                                              │
                                              ▼
                  make_integration_plots.m ──►  integration_plot.png + integration_report.csv
```

- **Simulink side runs:** the `.slx` model (driven by `export_frames.m`).
  Frame values come from the model's blocks (nonce, signature, counter,
  voltage); the `model_*` verdicts come from Vehicle_Node's comparison,
  Replay_Protection, Injection_Detection, and the Telemetry gate.
- **Python side runs:** `verify_frames.py`, using the repo's real code —
  `crypto/counters/replay_protection.py` (`ReplayProtection.validate`) for
  the replay check, plus the signature and voltage checks.

---

## PART 8 — The ECDSA question (say this proactively)

If asked "is this really crypto?":

> "The Simulink model uses a simplified signature value (`nonce + 100`)
> because it's a visualization of the bus flow — it can't run real ECDSA
> internally. The real ECDSA implementation is in our Python orchestrator,
> `run_battlock.py`: P-256 keypairs, the root CA, certificates, and the
> challenge–response handshake. That's the code that moves to the ATECC608
> hardware. We demonstrate both: the co-simulation proves the model matches
> our logic, and the orchestrator proves the real crypto works."

This is a deliberate two-layer design: the model is the demonstration, the
orchestrator is the product-grade implementation.

---

## PART 9 — If asked to explain the Simulink model

> "It simulates the BattLock CAN security flow: a battery authenticates to a
> vehicle, and telemetry only flows if authentication passes. It also lets
> us inject attacks to prove the defenses."

Top-level layout (7 subsystems): `Battery_Node` (data + signature +
counter), `Attack_Module` (can corrupt signature/counter/voltage),
`Vehicle_Node` (checks the signature), `State_Machine` (auth states),
`Replay_Protection` and `Injection_Detection` (the defenses), `Telemetry`
(gates SOC on auth), `Dashboard` (all displays).

- **Attack_Module:** three multi-port switches (one per signal). The
  `attack_mode` constant picks real or tampered values. Mode 0 = no attack,
  1 = replay, 2 = forged signature, 3 = injected voltage, 4 = dropped
  signature, 5 = combined spoof + injection.
- **State_Machine:** a Stateflow chart with 6 states matching our Python
  protocol: DISCONNECTED → HELLO_RECEIVED → CERT_VERIFIED →
  CHALLENGE_SENT → AUTHENTICATED → ACTIVE_SESSION. It only advances when
  the right condition holds.
- **Replay_Protection:** rejects any counter that isn't strictly increasing.
- **Injection_Detection:** flags voltage above 100 V.
- **Telemetry:** only outputs SOC when state == 5 (ACTIVE_SESSION) AND no
  replay/injection detected — so a detected attack stops the data too.

Anchor phrase: **"Battery proves who it is, the attacker tries to break
that, and the system catches it."**

---

## PART 10 — Speaking script

> "In BattLock, only authentic manufacturer-certified batteries should talk
> to the vehicle. Our system authenticates the battery, then only lets
> authenticated batteries stream telemetry.
>
> The Simulink model simulates the CAN bus: a battery node, a vehicle node,
> and an attack module that can inject replay, spoofing, injection, or
> dropped-signature attacks — or a combination.
>
> The model generates the actual frames. Then our real Python code — the
> same crypto and protocol we built — verifies every frame. The report shows
> Python and Simulink agree on all six attack scenarios, which verifies both
> the model and the real system. On the plot, the Python row and the
> Simulink row are identical.
>
> Separately, running the orchestrator shows the full ECDSA handshake end to
> end. Next phase, we move this to the ATECC608 hardware and real CAN."

---

## PART 11 — Team roles

| Team member | Job during demo |
|-------------|-----------------|
| Simulink lead | Run Route 1, open the plot/report, explain the model |
| Crypto lead | Field questions on ECDSA, certs, challenge–response |
| Protocol lead | Explain the state machine and session flow |
| Attack-testing lead | Explain each attack mode and the defense response |
| Anyone | Repeat the key line: "Simulink simulates the bus; our code decides" |

---

## PART 12 — Morning-of checklist

- [ ] Laptop charged, MATLAB + Python 3.11 open and tested once
- [ ] `cryptography` + `psutil` installed
- [ ] Run `run_integration` once from cold to confirm no surprises
- [ ] `integration_report.csv` + `integration_plot.png` backed up (screenshots in slides)
- [ ] 4-month roadmap ready (battery plant model, ATECC608 firmware, hardware CAN)
