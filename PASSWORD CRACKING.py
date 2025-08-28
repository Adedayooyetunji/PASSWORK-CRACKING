from argon2 import PasswordHasher
import bcrypt, math, time
from zxcvbn import zxcvbn

# --- 1) Secure hashing & verification (Argon2 recommended) ---
ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, salt_len=16)

def hash_password_argon2(plain: str) -> str:
    return ph.hash(plain)

def verify_password_argon2(hash_str: str, attempt: str) -> bool:
    try:
        ph.verify(hash_str, attempt)
        return True
    except Exception:
        return False

# Optional bcrypt (still widely used)
def hash_password_bcrypt(plain: str) -> bytes:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12))

def verify_password_bcrypt(hash_bytes: bytes, attempt: str) -> bool:
    return bcrypt.checkpw(attempt.encode(), hash_bytes)

# --- 2) Strength feedback (zxcvbn) ---
def strength_feedback(pw: str) -> dict:
    res = zxcvbn(pw)
    return {
        "score_0_to_4": res["score"],
        "crack_time_display": res["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "suggestions": res["feedback"]["suggestions"],
        "warning": res["feedback"]["warning"]
    }

# --- 3) Simple entropy & naive crack-time estimate (math only) ---
def charset_size(pw: str) -> int:
    lowers = any(c.islower() for c in pw)
    uppers = any(c.isupper() for c in pw)
    digits = any(c.isdigit() for c in pw)
    symbols = any(not c.isalnum() for c in pw)
    size = 0
    size += 26 if lowers else 0
    size += 26 if uppers else 0
    size += 10 if digits else 0
    # conservative common set ~33
    size += 33 if symbols else 0
    return max(size, 26)  # assume at least letters

def entropy_bits(pw: str) -> float:
    R = charset_size(pw)
    return len(pw) * math.log2(R)

def naive_offline_crack_time(pw: str, guesses_per_sec: float = 1e9) -> str:
    # Worst-case search space = R^L, average case ~ half
    R = charset_size(pw)
    space = R ** len(pw)
    avg_guesses = space / 2
    seconds = avg_guesses / guesses_per_sec
    # format
    units = [("years", 365*24*3600), ("days", 24*3600), ("hours", 3600), ("mins", 60), ("secs", 1)]
    parts = []
    for name, div in units:
        if seconds >= div:
            qty = int(seconds // div)
            seconds -= qty * div
            parts.append(f"{qty} {name}")
    return ", ".join(parts) or "under 1 sec"

# --- 4) Basic login + rate limiting demo ---
class LoginService:
    def _init_(self, policy_max_attempts=5, lockout_seconds=300):
        self.store = {}  # username -> stored hash (argon2 str)
        self.fail_counts = {}
        self.locked_until = {}
        self.max_attempts = policy_max_attempts
        self.lock_secs = lockout_seconds

    def register(self, username: str, password: str):
        self.store[username] = hash_password_argon2(password)
        self.fail_counts[username] = 0
        self.locked_until[username] = 0

    def login(self, username: str, password: str) -> bool:
        now = time.time()
        if username not in self.store:
            return False
        if now < self.locked_until[username]:
            return False
        ok = verify_password_argon2(self.store[username], password)
        if ok:
            self.fail_counts[username] = 0
            return True
        self.fail_counts[username] += 1
        if self.fail_counts[username] >= self.max_attempts:
            self.locked_until[username] = now + self.lock_secs
            self.fail_counts[username] = 0
        return False

# --- 5) Quick demo run ---
if _name_ == "_main_":
    pw = "Summer2025!"
    print("Strength:", strength_feedback(pw))
    print("Entropy (bits):", round(entropy_bits(pw), 1))
    print("Naive offline crack-time @1e9 guesses/s:", naive_offline_crack_time(pw))

    svc = LoginService()
    svc.register("alice", pw)
    print("Login correct:", svc.login("alice", "Summer2025!"))
    # simulate bad attempts
    for i in range(6):
        print("Login wrong:", svc.login("alice", "wrongpass"))