# Log watcher: detects possible brute-force login attempts and flags potential breaches

from datetime import datetime

LOG_FILE = "sample_week.log"

# Each rule says: "this many failures within this many seconds is suspicious"
RULES = [
    {"name": "fast burst", "threshold": 5, "window_seconds": 60},
    {"name": "slow burn", "threshold": 10, "window_seconds": 86400},
]


def has_burst(times, threshold, window_seconds):
    """Return True if there are `threshold` failures within `window_seconds`."""
    times.sort()
    for i in range(len(times) - threshold + 1):
        gap = times[i + threshold - 1] - times[i]
        if gap.total_seconds() <= window_seconds:
            return True
    return False


def failures_before(success_time, fail_times, window_seconds):
    """Count failures that happened shortly before a successful login."""
    count = 0
    for t in fail_times:
        gap = (success_time - t).total_seconds()
        if 0 <= gap <= window_seconds:
            count += 1
    return count


print("Log watcher starting...")

failed_times = {}
success_times = {}

with open(LOG_FILE) as f:
    for line in f:
        words = line.split()
        ip = words[-1]
        timestamp = datetime.strptime(words[0] + " " + words[1], "%Y-%m-%d %H:%M:%S")
        if "FAILED" in line:
            if ip not in failed_times:
                failed_times[ip] = []
            failed_times[ip].append(timestamp)
        elif "SUCCESS" in line:
            if ip not in success_times:
                success_times[ip] = []
            success_times[ip].append(timestamp)

for ip, times in failed_times.items():
    triggered = []
    compromised_at = []
    for rule in RULES:
        if has_burst(times, rule["threshold"], rule["window_seconds"]):
            triggered.append(rule["name"])
            for s in success_times.get(ip, []):
                if failures_before(s, times, rule["window_seconds"]) >= rule["threshold"]:
                    if s not in compromised_at:
                        compromised_at.append(s)
    if compromised_at:
        print(f"CRITICAL: {ip} logged in at {compromised_at[0]} after suspicious failures ({', '.join(triggered)}). Possible compromise.")
    elif triggered:
        print(f"ALERT: {ip} triggered: {', '.join(triggered)}")