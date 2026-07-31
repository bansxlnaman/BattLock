# BattLock — Monday Demo Guide

A one-page team brief plus exact step-by-step instructions for the Monday
evaluation. The goal of this demo: show that our Simulink model and our real
Python security code work together to verify the BattLock system.

---

## PART 1 — What we're showing (60-second pitch)

> BattLock protects EV battery-to-vehicle communication over CAN. Our demo
> proves it works by running a co-simulation: **the Simulink model simulates
> the CAN bus and generates frames; the real BattLock Python code verifies
> those frames.** We run six attack scenarios and the two independent
> implementations agree on every verdict.

Key line to repeat: **"Simulink simulates the bus. Our real code makes the
security decisions."**

---

## PART 2 — What the evaluator will see

| # | Demo step | What it shows |
|---|-----------|---------------|
| 1 | `run_integration` (one command) | Full pipeline: Simulink exports CAN frames → Python verifies → plot + report generated |
| 2 | Agreement table | Python and Simulink agree on all 6 attack modes (YES/YES/...) |
| 3 | `integration_plot.png` | Auth / replay / injection flags per mode |
| 4 | `python run_battlock.py` | The real ECDSA auth flow ending in ACTIVE_SESSION + metrics |

---

## PART 3 — Exact setup checklist (do this BEFORE Monday)

### Software on the demo machine
- [ ] MATLAB R2025a (with Simulink + Stateflow)
- [ ] Python 3.11
- [ ] `pip install cryptography psutil` in Python 3.11

### Files
The repo must be on the machine. We work in two folders:

- `<repo>/simulink/`  — the Simulink model + MATLAB scripts
- `<repo>/integration/` — the Python verifier (`verify_frames.py`)

### The model
File: `<repo>/simulink/Battlock_System2.slx`
(It was renamed from `Battlock_System-2.slx` because MATLAB model names
cannot contain a hyphen. Signal logging is already enabled on all outputs —
don't worry about that.)

---

## PART 4 — DEMO ROUTE 1: One-command co-simulation (RECOMMENDED)

This is the main demo. It does everything automatically. No Simulink
knowledge required.

### Steps (5 minutes, in the terminal)

1. **Open MATLAB** (just the app — the script drives Simulink for us).
2. **Set the working folder.** At the MATLAB command window, type:
   ```
   cd C:\...\BattLock\simulink
   ```
   (Use the real path to the repo on the machine.)
3. **Run the integration driver:**
   ```
   run_integration
   ```
4. **Watch it work.** Three phases print:
   ```
   [1/3] Exporting CAN frames from Simulink...
   [2/3] Verifying frames with real BattLock Python code...
   [3/3] Generating integration plot and report...
   ```
5. **When it finishes**, open the two files it produced (in the `simulink`
   folder) to show:
   - `integration_report.csv`  — the agreement table (every mode = YES)
   - `integration_plot.png`    — the per-mode flags plot

### What the agreement table means (memorize this)

```
mode  attack                    py_auth  mdl_auth  agree
0     No attack                   1        1       YES   <- normal battery works
1     Replay                      1        1       YES   <- replay detected
2     Signature spoof             0        0       YES   <- forged signature rejected
3     Voltage injection           1        1       YES   <- injected voltage detected
4     Signature drop              0        0       YES   <- dropped signature rejected
5     Spoof + voltage injection   0        0       YES   <- both caught at once
```

- `py_*` = verdict from **our Python code** (the real implementation)
- `mdl_*` = verdict from the **Simulink model** (independent)
- They match → the model faithfully represents our real system.

---

## PART 5 — DEMO ROUTE 2: Show the real Python security stack

Run this in the terminal (from `<repo>`), separately from MATLAB:

```
python run_battlock.py
```

You'll see the full authentication flow print out:

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

This shows the **real cryptography**: ECDSA keypairs, certificates, the
challenge–response handshake, session creation, replay protection. This is
the code that the co-simulation's verification decisions are built on.

**Why show both?** Route 1 proves the model matches our code; Route 2 shows
the code actually does real crypto. Together they answer: "is this real, or
just a pretty model?"

---

## PART 6 — DEMO ROUTE 3 (optional): Attack mode deep-dive

If they want to see attacks live, inside the model:

1. Open `Battlock_System2.slx` (double-click the file, or in MATLAB:
   `open_system('Battlock_System2')`).
2. Double-click the **Attack_Module** subsystem.
3. Find the block **Constant5** (it has value `0`). Double-click it.
4. Change the **Constant value** to one of these, then press OK:
   - `1` → replay attack (stale counter) → `replay_detected` lights up
   - `2` → signature spoofing → auth blocked, no telemetry
   - `3` → voltage injection (999 V) → `injection_detected` lights up
   - `4` → signature dropping → auth blocked
   - `5` → spoof + voltage injection → auth blocked AND `injection_detected` lights up
5. Press **Run** (green play button in the model toolbar). Let it run 10 s.
6. Open the **Dashboard** subsystem and watch the displays/scopes.

IMPORTANT: set the value back to `0` when done, or save the model.

---

## PART 7 — What you're saying while demoing (a script)

> "In BattLock, only authentic manufacturer-certified batteries should talk
> to the vehicle. Our system authenticates the battery, then only lets
> authenticated batteries stream telemetry.
>
> The Simulink model simulates the CAN bus: a battery node, a vehicle node,
> and an attack module that can inject replay, spoofing, injection, or
> dropped-signature attacks.
>
> The model generates the actual frames. Then our real Python code — the
> same crypto and protocol we built — verifies every frame. The report shows
> Python and Simulink agree on all six attack scenarios, which verifies both
> the model and the real system.
>
> Separately, running the orchestrator shows the full ECDSA handshake end to
> end. Next phase, we move this to the ATECC608 hardware and real CAN."

---

## PART 8 — Honest caveat (say this proactively)

The model's signature value is a simplified stand-in (`nonce + 100`), not
the full ECDSA. That's fine — the model's job is to simulate the bus and the
frame traffic. The **security decisions** come from our real Python code,
and the full ECDSA handshake is demonstrated by `run_battlock.py`. Say this
yourself before the evaluator asks.

---

## PART 9 — Team roles on the day

| Team member | Job during demo |
|-------------|-----------------|
| Simulink lead | Run Route 1, open the plot/report, explain the model |
| Crypto lead | Field questions on ECDSA, certs, challenge–response |
| Protocol lead | Explain the state machine and session flow |
| Attack-testing lead | Explain each attack mode and the defense response |
| Anyone | Repeat the key line: "Simulink simulates the bus; our code decides" |

---

## PART 10 — Last-minute checklist (morning of Monday)

- [ ] Laptop charged, MATLAB + Python 3.11 open and tested once
- [ ] `cryptography` + `psutil` installed
- [ ] Run `run_integration` once from cold to confirm no surprises
- [ ] `integration_report.csv` + `integration_plot.png` backed up (screenshots in slides)
- [ ] 4-month roadmap ready (battery plant model, ATECC608 firmware, hardware CAN)
