"""
Telemetry Flow Animation — Interactive Attack Injection
========================================================
Click on any device node to inject an attack.
Packets turn red, trust score drops, alerts fire.

Run:  python visualizations/telemetry_flow_animation.py
"""

import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.animation import FuncAnimation
import numpy as np
import os

# ── Paths ──
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

# ── Colors ──
DEVICE_COLORS = {
    "CCTV_01":   "#3b82f6",   # Blue
    "Router_01": "#22c55e",   # Green
    "Access_01": "#a855f7",   # Purple
}
ALERT_COLOR   = "#ef4444"    # Red
BG_COLOR      = "#0f172a"    # Dark navy
PANEL_BG      = "#1e293b"    # Slightly lighter
TEXT_COLOR     = "#e2e8f0"   # Light gray
MUTED_COLOR    = "#64748b"   # Muted
NODE_COLOR     = "#334155"   # Node fill
NODE_BORDER    = "#475569"   # Node border
EDGE_COLOR     = "#334155"   # Edge lines

# ── Layout ──
DEVICE_POS = {
    "CCTV_01":   (0.12, 0.72),
    "Router_01": (0.12, 0.50),
    "Access_01": (0.12, 0.28),
}
DETECT_POS = (0.45, 0.50)
TRUST_POS  = (0.78, 0.50)

DEVICE_LABELS = {
    "CCTV_01":   ("CCTV 01",    "IP Camera"),
    "Router_01": ("Router 01",  "DNS Forwarder"),
    "Access_01": ("Access 01",  "Badge Reader"),
}

# Attack descriptions per device
ATTACK_INFO = {
    "CCTV_01": {
        "type": "Data Exfiltration + C2",
        "detail": "SSH to external IP, bandwidth 5x spike",
        "policy": "HARD_VIOLATION",
        "drift": "DRIFT_STRONG",
    },
    "Router_01": {
        "type": "Lateral Scanning",
        "detail": "TCP scan on ports 22, 445, 3389",
        "policy": "HARD_VIOLATION",
        "drift": "DRIFT_STRONG",
    },
    "Access_01": {
        "type": "Credential Stuffing",
        "detail": "Burst auth requests to unknown server",
        "policy": "HARD_VIOLATION",
        "drift": "DRIFT_STRONG",
    },
}

# ── State ──
attack_state = {dev: False for dev in DEVICE_COLORS}
trust_scores = {"CCTV_01": 92.0, "Router_01": 88.0, "Access_01": 95.0}
trust_targets = {"CCTV_01": 92.0, "Router_01": 88.0, "Access_01": 95.0}
NORMAL_TRUST  = {"CCTV_01": 92.0, "Router_01": 88.0, "Access_01": 95.0}
ATTACK_TRUST  = {"CCTV_01": 12.0, "Router_01": 18.0, "Access_01": 8.0}
alert_queue = []       # list of (device_id, remaining_frames)
frame_counter = [0]
data_processed_mb = [0.0]
TOTAL_DATA_MB = 847.5  # from real data

# Deduction breakdown (for display)
deductions = {
    dev: {"anomaly": 0.0, "drift": 0.0, "policy": 0.0}
    for dev in DEVICE_COLORS
}
ATTACK_DEDUCTIONS = {
    "CCTV_01":   {"anomaly": 38.0, "drift": 20.0, "policy": 40.0},
    "Router_01": {"anomaly": 30.0, "drift": 20.0, "policy": 40.0},
    "Access_01": {"anomaly": 35.0, "drift": 20.0, "policy": 40.0},
}


# ── Particle System ──
class Particle:
    def __init__(self, start, end, color, device_id=None):
        self.start = np.array(start, dtype=float)
        self.end = np.array(end, dtype=float)
        self.original_color = color
        self.color = color
        self.device_id = device_id
        self.t = np.random.uniform(0, 1)
        self.speed = 0.006 + np.random.uniform(0, 0.004)
        self.normal_speed = self.speed
        self.size = np.random.uniform(30, 60)

    def update(self):
        self.t += self.speed
        if self.t > 1.0:
            self.t -= 1.0

    @property
    def pos(self):
        mid = (self.start + self.end) / 2
        mid[1] += 0.025 * np.sin(self.t * np.pi)
        t = self.t
        return (1-t)**2 * self.start + 2*(1-t)*t * mid + t**2 * self.end


# Build particles
particles_s1 = []  # Devices → Detection
particles_s2 = []  # Detection → Trust

for dev_id, pos in DEVICE_POS.items():
    for _ in range(8):
        particles_s1.append(Particle(pos, DETECT_POS, DEVICE_COLORS[dev_id], dev_id))
    for _ in range(3):
        particles_s2.append(Particle(DETECT_POS, TRUST_POS, DEVICE_COLORS[dev_id], dev_id))


# ── Figure ──
fig = plt.figure(figsize=(16, 9), facecolor=BG_COLOR)
fig.subplots_adjust(left=0.02, right=0.98, top=0.95, bottom=0.05)
ax = fig.add_subplot(111)

fig.text(0.50, 0.97, "IoT TRUST & DRIFT — TELEMETRY FLOW PIPELINE",
         fontsize=16, fontweight='bold', color=TEXT_COLOR,
         ha='center', va='top', fontfamily='monospace')
fig.text(0.50, 0.937, "Click a device to inject an attack  |  Click again to restore",
         fontsize=9, color=MUTED_COLOR, ha='center', va='top', fontfamily='monospace')


# ── Click Handler ──
def on_click(event):
    if event.inaxes != ax:
        return
    mx, my = event.xdata, event.ydata
    if mx is None or my is None:
        return

    for dev_id, (dx, dy) in DEVICE_POS.items():
        if abs(mx - dx) < 0.10 and abs(my - dy) < 0.08:
            # Toggle attack state
            attack_state[dev_id] = not attack_state[dev_id]

            if attack_state[dev_id]:
                trust_targets[dev_id] = ATTACK_TRUST[dev_id]
                alert_queue.append((dev_id, 120))  # Show alert for 120 frames
            else:
                trust_targets[dev_id] = NORMAL_TRUST[dev_id]
                deductions[dev_id] = {"anomaly": 0.0, "drift": 0.0, "policy": 0.0}
            break

fig.canvas.mpl_connect('button_press_event', on_click)


# ── Drawing Helpers ──
def draw_box(x, y, w, h, fill, border, alpha=0.9):
    box = mpatches.FancyBboxPatch(
        (x - w/2, y - h/2), w, h,
        boxstyle="round,pad=0.012",
        facecolor=fill, edgecolor=border,
        linewidth=1.5, alpha=alpha, zorder=2
    )
    ax.add_patch(box)


def severity_of(score):
    if score >= 81: return "Low",    "#22c55e"
    if score >= 61: return "Medium", "#f59e0b"
    if score >= 31: return "High",   "#f97316"
    return                "Critical","#ef4444"


# ── Animation ──
def animate(frame):
    ax.clear()
    ax.set_facecolor(BG_COLOR)
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(0.0, 1.0)
    ax.axis('off')
    frame_counter[0] = frame

    # Smoothly animate trust scores toward targets
    for dev_id in trust_scores:
        current = trust_scores[dev_id]
        target = trust_targets[dev_id]
        diff = target - current
        trust_scores[dev_id] = current + diff * 0.04  # Smooth transition

        # Smoothly animate deductions
        if attack_state[dev_id]:
            for key in deductions[dev_id]:
                dtarget = ATTACK_DEDUCTIONS[dev_id][key]
                dcurrent = deductions[dev_id][key]
                deductions[dev_id][key] = dcurrent + (dtarget - dcurrent) * 0.04

    # Data processed ticker
    data_processed_mb[0] = min(TOTAL_DATA_MB, data_processed_mb[0] + 0.18)

    # ── Column Labels ──
    ax.text(0.12, 0.93, "DATA SOURCES", fontsize=9, fontweight='bold',
            color=MUTED_COLOR, ha='center', fontfamily='monospace')
    ax.text(DETECT_POS[0], 0.93, "PROCESSING", fontsize=9, fontweight='bold',
            color=MUTED_COLOR, ha='center', fontfamily='monospace')
    ax.text(TRUST_POS[0], 0.93, "OUTPUT", fontsize=9, fontweight='bold',
            color=MUTED_COLOR, ha='center', fontfamily='monospace')

    # ── Device Nodes ──
    for dev_id, (x, y) in DEVICE_POS.items():
        is_attacked = attack_state[dev_id]
        border = ALERT_COLOR if is_attacked else NODE_BORDER
        fill = "#2a1215" if is_attacked else NODE_COLOR
        draw_box(x, y, 0.16, 0.13, fill, border)

        name, subtitle = DEVICE_LABELS[dev_id]
        name_color = ALERT_COLOR if is_attacked else DEVICE_COLORS[dev_id]

        ax.text(x, y + 0.03, name, fontsize=10, fontweight='bold',
                color=name_color, ha='center', va='center', zorder=5, fontfamily='monospace')
        ax.text(x, y - 0.005, subtitle, fontsize=7.5, color=MUTED_COLOR,
                ha='center', va='center', zorder=5, fontfamily='monospace')

        # Status badge
        if is_attacked:
            ax.text(x, y - 0.04, "COMPROMISED", fontsize=7, fontweight='bold',
                    color=ALERT_COLOR, ha='center', va='center', zorder=5, fontfamily='monospace')
        else:
            ax.text(x, y - 0.04, "NORMAL", fontsize=7, fontweight='bold',
                    color="#22c55e", ha='center', va='center', zorder=5, fontfamily='monospace')

    # ── Detection Engine Node ──
    any_attack = any(attack_state.values())
    det_border = "#f59e0b" if not any_attack else ALERT_COLOR
    draw_box(DETECT_POS[0], DETECT_POS[1], 0.18, 0.24, NODE_COLOR, det_border)
    ax.text(DETECT_POS[0], DETECT_POS[1] + 0.07, "DETECTION", fontsize=10, fontweight='bold',
            color=det_border, ha='center', va='center', zorder=5, fontfamily='monospace')
    ax.text(DETECT_POS[0], DETECT_POS[1] + 0.03, "ENGINE", fontsize=10, fontweight='bold',
            color=det_border, ha='center', va='center', zorder=5, fontfamily='monospace')
    layers = ["Isolation Forest", "Z-Score Drift", "Policy Rules"]
    for i, layer in enumerate(layers):
        ax.text(DETECT_POS[0], DETECT_POS[1] - 0.02 - i*0.032, f"• {layer}",
                fontsize=7.5, color=MUTED_COLOR, ha='center', va='center', zorder=5, fontfamily='monospace')

    # ── Trust Engine Node ──
    trust_border = "#3b82f6" if not any_attack else ALERT_COLOR
    draw_box(TRUST_POS[0], TRUST_POS[1], 0.18, 0.24, NODE_COLOR, trust_border)
    ax.text(TRUST_POS[0], TRUST_POS[1] + 0.07, "TRUST", fontsize=10, fontweight='bold',
            color=trust_border, ha='center', va='center', zorder=5, fontfamily='monospace')
    ax.text(TRUST_POS[0], TRUST_POS[1] + 0.03, "ENGINE", fontsize=10, fontweight='bold',
            color=trust_border, ha='center', va='center', zorder=5, fontfamily='monospace')
    sub = ["Score 0-100", "EMA Smoothing", "Severity Map"]
    for i, s in enumerate(sub):
        ax.text(TRUST_POS[0], TRUST_POS[1] - 0.02 - i*0.032, f"• {s}",
                fontsize=7.5, color=MUTED_COLOR, ha='center', va='center', zorder=5, fontfamily='monospace')

    # ── Edge Lines ──
    for dev_id, (x, y) in DEVICE_POS.items():
        is_att = attack_state[dev_id]
        ec = ALERT_COLOR if is_att else EDGE_COLOR
        ea = 0.7 if is_att else 0.3
        ew = 2.5 if is_att else 1.5
        ax.plot([x + 0.08, DETECT_POS[0] - 0.09], [y, DETECT_POS[1]],
                color=ec, linewidth=ew, alpha=ea, zorder=1, linestyle='--' if not is_att else '-')

    out_ec = ALERT_COLOR if any_attack else EDGE_COLOR
    out_ea = 0.7 if any_attack else 0.3
    ax.plot([DETECT_POS[0] + 0.09, TRUST_POS[0] - 0.09], [DETECT_POS[1], TRUST_POS[1]],
            color=out_ec, linewidth=2.5 if any_attack else 2, alpha=out_ea, zorder=1,
            linestyle='-' if any_attack else '--')

    # ── Particles Stage 1 ──
    for p in particles_s1:
        if attack_state.get(p.device_id, False):
            p.color = ALERT_COLOR
            p.speed = p.normal_speed * 1.6  # Faster during attack (data exfil)
        else:
            p.color = p.original_color
            p.speed = p.normal_speed
        p.update()
        pos = p.pos
        glow_alpha = 0.3 if attack_state.get(p.device_id, False) else 0.0
        if glow_alpha > 0:
            ax.scatter(pos[0], pos[1], s=p.size * 2.5, c=ALERT_COLOR, alpha=glow_alpha,
                       edgecolors='none', zorder=2)
        ax.scatter(pos[0], pos[1], s=p.size, c=p.color, alpha=0.85,
                   edgecolors='none', zorder=3)

    # ── Particles Stage 2 ──
    for p in particles_s2:
        if attack_state.get(p.device_id, False):
            p.color = ALERT_COLOR
            p.speed = p.normal_speed * 1.4
        else:
            p.color = p.original_color
            p.speed = p.normal_speed
        p.update()
        pos = p.pos
        ax.scatter(pos[0], pos[1], s=p.size * 0.8, c=p.color, alpha=0.7,
                   edgecolors='none', zorder=3)

    # ── Trust Score Badges (right) ──
    for i, dev_id in enumerate(["CCTV_01", "Router_01", "Access_01"]):
        score = trust_scores[dev_id]
        sev_label, sev_color = severity_of(score)
        bx, by = 0.93, 0.82 - i * 0.11

        badge_border = ALERT_COLOR if attack_state[dev_id] else sev_color
        draw_box(bx, by, 0.13, 0.085, PANEL_BG, badge_border, alpha=0.95)

        ax.text(bx, by + 0.025, dev_id.replace("_", " "), fontsize=7, fontweight='bold',
                color=TEXT_COLOR, ha='center', va='center', zorder=5, fontfamily='monospace')
        ax.text(bx, by, f"{score:.0f}", fontsize=14, fontweight='bold',
                color=sev_color, ha='center', va='center', zorder=5, fontfamily='monospace')
        ax.text(bx, by - 0.028, sev_label, fontsize=7, fontweight='bold',
                color=sev_color, ha='center', va='center', zorder=5, fontfamily='monospace')

    # ── Deduction Breakdown (below trust badges, when attack active) ──
    attacked_devs = [d for d in DEVICE_COLORS if attack_state[d]]
    if attacked_devs:
        dev_show = attacked_devs[0]
        d = deductions[dev_show]
        bx_d = 0.93
        by_d = 0.46

        draw_box(bx_d, by_d, 0.13, 0.16, PANEL_BG, ALERT_COLOR, alpha=0.9)
        ax.text(bx_d, by_d + 0.06, "DEDUCTIONS", fontsize=7, fontweight='bold',
                color=ALERT_COLOR, ha='center', va='center', zorder=5, fontfamily='monospace')
        ax.text(bx_d, by_d + 0.032, dev_show.replace("_", " "), fontsize=6.5,
                color=MUTED_COLOR, ha='center', va='center', zorder=5, fontfamily='monospace')

        ax.text(bx_d - 0.045, by_d + 0.005, "Anomaly", fontsize=6.5,
                color=MUTED_COLOR, ha='left', va='center', zorder=5, fontfamily='monospace')
        ax.text(bx_d + 0.05, by_d + 0.005, f"-{d['anomaly']:.0f}", fontsize=7, fontweight='bold',
                color="#f97316", ha='right', va='center', zorder=5, fontfamily='monospace')

        ax.text(bx_d - 0.045, by_d - 0.02, "Drift", fontsize=6.5,
                color=MUTED_COLOR, ha='left', va='center', zorder=5, fontfamily='monospace')
        ax.text(bx_d + 0.05, by_d - 0.02, f"-{d['drift']:.0f}", fontsize=7, fontweight='bold',
                color="#f59e0b", ha='right', va='center', zorder=5, fontfamily='monospace')

        ax.text(bx_d - 0.045, by_d - 0.045, "Policy", fontsize=6.5,
                color=MUTED_COLOR, ha='left', va='center', zorder=5, fontfamily='monospace')
        ax.text(bx_d + 0.05, by_d - 0.045, f"-{d['policy']:.0f}", fontsize=7, fontweight='bold',
                color=ALERT_COLOR, ha='right', va='center', zorder=5, fontfamily='monospace')

        total_ded = d['anomaly'] + d['drift'] + d['policy']
        ax.text(bx_d, by_d - 0.068, f"Total: -{total_ded:.0f} pts", fontsize=7, fontweight='bold',
                color=ALERT_COLOR, ha='center', va='center', zorder=5, fontfamily='monospace')

    # ── Alert Banner ──
    # Remove expired alerts
    alive = []
    for dev_id, remaining in alert_queue:
        if remaining > 0:
            alive.append((dev_id, remaining - 1))
    alert_queue.clear()
    alert_queue.extend(alive)

    if alert_queue:
        latest_dev = alert_queue[-1][0]
        info = ATTACK_INFO[latest_dev]

        draw_box(0.45, 0.885, 0.42, 0.075, "#1c1017", ALERT_COLOR, alpha=0.95)

        blink = frame % 24 < 16
        if blink:
            ax.text(0.28, 0.895, "!", fontsize=14, fontweight='bold',
                    color=ALERT_COLOR, ha='center', va='center', zorder=6, fontfamily='monospace')

        ax.text(0.45, 0.905, f"ANOMALY DETECTED — {latest_dev.replace('_', ' ')}", fontsize=9,
                fontweight='bold', color=ALERT_COLOR, ha='center', va='center',
                zorder=6, fontfamily='monospace')
        ax.text(0.45, 0.878, f"{info['type']}  |  {info['detail']}", fontsize=7,
                color="#fca5a5", ha='center', va='center', zorder=6, fontfamily='monospace')
        ax.text(0.45, 0.856, f"Policy: {info['policy']}  |  Drift: {info['drift']}",
                fontsize=6.5, color="#fb7185", ha='center', va='center', zorder=6, fontfamily='monospace')

    # ── Bottom Metrics Panel ──
    draw_box(0.50, 0.075, 0.94, 0.10, PANEL_BG, NODE_BORDER, alpha=0.9)

    # Status
    status_label = "UNDER ATTACK" if any_attack else "ALL SYSTEMS NORMAL"
    status_color = ALERT_COLOR if any_attack else "#22c55e"
    ax.text(0.07, 0.095, "STATUS", fontsize=6.5, color=MUTED_COLOR,
            ha='left', va='center', zorder=5, fontfamily='monospace')
    ax.text(0.07, 0.065, status_label, fontsize=8.5, fontweight='bold', color=status_color,
            ha='left', va='center', zorder=5, fontfamily='monospace')

    # Devices under attack count
    n_attacked = sum(attack_state.values())
    ax.text(0.28, 0.095, "COMPROMISED", fontsize=6.5, color=MUTED_COLOR,
            ha='left', va='center', zorder=5, fontfamily='monospace')
    ax.text(0.28, 0.065, f"{n_attacked} / 3 devices", fontsize=9, fontweight='bold',
            color=ALERT_COLOR if n_attacked > 0 else "#22c55e",
            ha='left', va='center', zorder=5, fontfamily='monospace')

    # Data processed
    pct = min(100, data_processed_mb[0] / TOTAL_DATA_MB * 100)
    ax.text(0.46, 0.095, "DATA PROCESSED", fontsize=6.5, color=MUTED_COLOR,
            ha='left', va='center', zorder=5, fontfamily='monospace')
    ax.text(0.46, 0.065, f"{data_processed_mb[0]:.0f} / {TOTAL_DATA_MB:.0f} MB  ({pct:.0f}%)",
            fontsize=8, fontweight='bold', color=TEXT_COLOR,
            ha='left', va='center', zorder=5, fontfamily='monospace')

    # Traffic share
    ax.text(0.70, 0.095, "TRAFFIC SHARE", fontsize=6.5, color=MUTED_COLOR,
            ha='left', va='center', zorder=5, fontfamily='monospace')
    ax.text(0.70, 0.065, "CCTV 78%", fontsize=7.5, fontweight='bold',
            color=DEVICE_COLORS["CCTV_01"], ha='left', va='center', zorder=5, fontfamily='monospace')
    ax.text(0.80, 0.065, "Router 19%", fontsize=7.5, fontweight='bold',
            color=DEVICE_COLORS["Router_01"], ha='left', va='center', zorder=5, fontfamily='monospace')
    ax.text(0.92, 0.065, "Access 3%", fontsize=7.5, fontweight='bold',
            color=DEVICE_COLORS["Access_01"], ha='left', va='center', zorder=5, fontfamily='monospace')

    return []


# ── Run ──
print("=" * 55)
print("  IoT Trust & Drift — Telemetry Flow Animation")
print("=" * 55)
print()
print("  CONTROLS:")
print("    Click a DEVICE NODE to inject an attack")
print("    Click it again to restore normal state")
print("    Close the window to exit")
print()
print("=" * 55)

anim = FuncAnimation(fig, animate, frames=None, interval=50, blit=False, cache_frame_data=False)
plt.show()
