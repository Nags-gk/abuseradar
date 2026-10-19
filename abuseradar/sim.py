"""Synthetic telemetry for a consumer smart-home device cloud, with labeled attacks.

The simulated service has user accounts, paired home devices (thermostats, cameras,
trackers) that check in on a schedule, a login endpoint, and a device API. Benign
users log in from home, from mobile networks, and sometimes while travelling. Attack
campaigns are injected on top and every attacker event carries a label, so detection
quality can be measured instead of eyeballed.

All data is synthetic. No real users, IPs or credentials are involved.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

# (country, lat, lon, utc_offset_hours, weight)
COUNTRIES = [
    ("US", 39.8, -98.6, -6, 0.42), ("CA", 56.1, -106.3, -5, 0.06), ("GB", 54.0, -2.0, 0, 0.08),
    ("DE", 51.2, 10.4, 1, 0.07), ("FR", 46.6, 2.2, 1, 0.05), ("IN", 21.0, 78.0, 5.5, 0.08),
    ("JP", 36.2, 138.3, 9, 0.05), ("BR", -14.2, -51.9, -3, 0.05), ("AU", -25.3, 133.8, 10, 0.04),
    ("MX", 23.6, -102.6, -6, 0.03), ("SG", 1.35, 103.8, 8, 0.02), ("NL", 52.1, 5.3, 1, 0.02),
    ("RU", 61.5, 105.3, 3, 0.01), ("VN", 14.1, 108.3, 7, 0.01), ("NG", 9.1, 8.7, 1, 0.01),
]
CC = [c[0] for c in COUNTRIES]
GEO = {c[0]: (c[1], c[2], c[3]) for c in COUNTRIES}

BENIGN_UA = ["HomeApp/5.2 iOS", "HomeApp/5.2 Android", "HomeApp/5.1 Android", "Mozilla/5.0 Chrome/129",
             "Mozilla/5.0 Safari/18", "Mozilla/5.0 Firefox/131"]
ATTACK_UA = ["python-requests/2.32", "okhttp/4.12", "Go-http-client/1.1", "Mozilla/5.0 Chrome/129",
             "curl/8.9"]


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = np.radians(lat1), np.radians(lat2)
    dp, dl = p2 - p1, np.radians(np.asarray(lon2) - np.asarray(lon1))
    a = np.sin(dp / 2) ** 2 + np.cos(p1) * np.cos(p2) * np.sin(dl / 2) ** 2
    return 2 * r * np.arcsin(np.sqrt(a))


def pw_hash(secret: str) -> str:
    """Keyed hash of an attempted password. Services that log a short keyed hash of
    attempted credentials can spot one password being tried across many accounts
    (spraying) without ever storing passwords."""
    return hashlib.sha256(("pepper:" + secret).encode()).hexdigest()[:12]


@dataclass
class Config:
    accounts: int = 4000
    days: int = 21
    seed: int = 7
    start: str = "2026-09-01"
    checkins_per_day: int = 6


@dataclass
class World:
    rng: np.random.Generator
    asns: pd.DataFrame
    accounts: pd.DataFrame
    devices: pd.DataFrame
    rows: list = field(default_factory=list)
    campaigns: list = field(default_factory=list)


def _build_asns(rng) -> pd.DataFrame:
    recs, asn = [], 64512
    for c in CC:
        for kind, n in (("residential", 4), ("mobile", 2), ("hosting", 2)):
            for _ in range(n):
                recs.append((asn, c, kind))
                asn += 1
    df = pd.DataFrame(recs, columns=["asn", "country", "asn_type"])
    df["ip_base"] = [(10 + i) << 24 for i in range(len(df))]  # one /8-style block per ASN
    return df


class IPPool:
    def __init__(self, asns: pd.DataFrame, rng):
        self.asns, self.rng = asns.set_index("asn"), rng
        self.by_kind = {(r.country, r.asn_type): [] for r in asns.itertuples()}
        for r in asns.itertuples():
            self.by_kind[(r.country, r.asn_type)].append(r.asn)

    def ip(self, country: str, kind: str) -> tuple[str, int]:
        asn = int(self.rng.choice(self.by_kind[(country, kind)]))
        base = int(self.asns.loc[asn, "ip_base"])
        n = base + int(self.rng.integers(1, 2 ** 22))
        return f"{n >> 24 & 255}.{n >> 16 & 255}.{n >> 8 & 255}.{n & 255}", asn


def _geo_jitter(rng, country):
    lat, lon, _ = GEO[country]
    return lat + rng.normal(0, 2.0), lon + rng.normal(0, 2.5)


def build_world(cfg: Config) -> tuple[World, IPPool]:
    rng = np.random.default_rng(cfg.seed)
    asns = _build_asns(rng)
    pool = IPPool(asns, rng)
    w = np.array([c[4] for c in COUNTRIES]); w = w / w.sum()
    home = rng.choice(CC, size=cfg.accounts, p=w)
    acc = []
    for i, c in enumerate(home):
        ip, asn = pool.ip(c, "residential")
        mip, masn = pool.ip(c, "mobile")
        lat, lon = _geo_jitter(rng, c)
        acc.append(dict(account_id=f"a{i:05d}", country=c, home_ip=ip, home_asn=asn, mobile_ip=mip,
                        mobile_asn=masn, lat=lat, lon=lon, fp=f"fp{rng.integers(1, 2**40):010x}",
                        ua=str(rng.choice(BENIGN_UA)), password=f"pw-{i}-{rng.integers(1e9)}",
                        reused_pw=bool(rng.random() < 0.03), vpn=bool(rng.random() < 0.04),
                        integration=bool(rng.random() < 0.03)))
    accounts = pd.DataFrame(acc)
    devs = []
    for a in accounts.itertuples():
        for _ in range(int(rng.integers(1, 4))):
            devs.append(dict(device_id=f"d{len(devs):06d}", account_id=a.account_id))
    return World(rng, asns, accounts, pd.DataFrame(devs)), pool


def _row(w: World, ts, etype, account, ip, asn, lat, lon, fp="", ua="", success=True, pw="",
         device_id="", endpoint="", status=200, label="", attack=""):
    w.rows.append((ts, etype, account, ip, asn, lat, lon, fp, ua, success, pw, device_id, endpoint,
                   status, label, attack))


def _diurnal_ts(rng, day0: pd.Timestamp, offset: float, n: int) -> list:
    # local waking hours 7-23, peaking in the evening
    hours = np.clip(rng.normal(18.5, 3.5, n), 7, 23.9)
    return [day0 + pd.Timedelta(hours=float(h - offset)) for h in hours]


def simulate_benign(w: World, pool: IPPool, cfg: Config):
    rng, start = w.rng, pd.Timestamp(cfg.start, tz="UTC")
    accts = w.accounts
    travellers = sorted(rng.choice(accts.account_id, size=int(0.03 * len(accts)), replace=False))
    trips = {}
    for a in travellers:
        d0 = int(rng.integers(1, cfg.days - 4))
        dest = str(rng.choice([c for c in CC if c != accts.set_index("account_id").loc[a, "country"]]))
        trips[a] = (d0, d0 + int(rng.integers(2, 6)), dest)
    devmap = w.devices.groupby("account_id").device_id.apply(list).to_dict()
    for a in accts.itertuples():
        off = GEO[a.country][2]
        mydevs = devmap[a.account_id]
        hotel = None
        for d in range(cfg.days):
            day0 = start + pd.Timedelta(days=d)
            trip = trips.get(a.account_id)
            away = trip is not None and trip[0] <= d < trip[1]
            if away:
                if hotel is None:
                    hotel = pool.ip(trip[2], "residential"), _geo_jitter(rng, trip[2])
                (ip, asn), (lat, lon) = hotel
                toff = GEO[trip[2]][2]
            else:
                hotel = None
            n = int(rng.poisson(1.1))
            for ts in _diurnal_ts(rng, day0, toff if away else off, n):
                if not away:
                    if rng.random() < 0.78:
                        ip, asn, lat, lon = a.home_ip, a.home_asn, a.lat, a.lon
                    else:
                        ip, asn, lat, lon = a.mobile_ip, a.mobile_asn, a.lat + rng.normal(0, .2), a.lon + rng.normal(0, .2)
                if not away and a.vpn and rng.random() < 0.5:  # commercial VPN exits are hosting ASNs
                    vc = str(rng.choice(["US", "NL", "DE", "SG"]))
                    (ip, asn), (lat, lon) = pool.ip(vc, "hosting"), _geo_jitter(rng, vc)
                fp = a.fp if rng.random() > 0.04 else f"fp{rng.integers(1, 2**40):010x}"
                ua = "HomeAutomation/2026.9 python-aiohttp" if a.integration and rng.random() < 0.6 else a.ua
                if rng.random() < 0.01:  # mistyped username: a failure on an account that does not exist
                    _row(w, ts - pd.Timedelta(seconds=20), "login", f"u{rng.integers(1e9)}", ip, asn, lat, lon, fp, ua,
                         False, pw_hash(a.password), status=401)
                if rng.random() < 0.05:  # typo, then success
                    _row(w, ts, "login", a.account_id, ip, asn, lat, lon, fp, ua, False, pw_hash(a.password + "x"), status=401)
                    ts = ts + pd.Timedelta(seconds=float(rng.integers(5, 60)))
                _row(w, ts, "login", a.account_id, ip, asn, lat, lon, fp, ua, True, pw_hash(a.password))
                for _ in range(int(rng.poisson(3))):
                    t2 = ts + pd.Timedelta(minutes=float(rng.uniform(0, 30)))
                    _row(w, t2, "api_call", a.account_id, ip, asn, lat, lon, fp, a.ua,
                         device_id=mydevs[int(rng.integers(len(mydevs)))], endpoint="GET /v1/devices/{id}")
            if rng.random() < 0.002:
                _row(w, day0 + pd.Timedelta(hours=float(rng.uniform(14, 26) - off)), "mfa_change",
                     a.account_id, a.home_ip, a.home_asn, a.lat, a.lon, a.fp, a.ua)
            if rng.random() < 0.003:
                _row(w, day0 + pd.Timedelta(hours=float(rng.uniform(14, 26) - off)), "device_pair",
                     a.account_id, a.home_ip, a.home_asn, a.lat, a.lon, a.fp, a.ua,
                     device_id=f"dnew{rng.integers(1e9)}")
    # devices check in from the home network on a fixed cadence
    acc_idx = accts.set_index("account_id")
    step = 24 / cfg.checkins_per_day
    for dv in w.devices.itertuples():
        a = acc_idx.loc[dv.account_id]
        phase = rng.uniform(0, step)
        n = int(cfg.days * cfg.checkins_per_day)
        for k in range(n):
            ts = start + pd.Timedelta(hours=float(phase + k * step + rng.normal(0, 0.05)))
            _row(w, ts, "device_checkin", dv.account_id, a.home_ip, a.home_asn, a.lat, a.lon,
                 device_id=dv.device_id, ua="DeviceAgent/3.4", endpoint="POST /v1/checkin")
    # benign signups trickle in
    for d in range(cfg.days):
        for _ in range(int(rng.poisson(6))):
            c = str(rng.choice(CC))
            ip, asn = pool.ip(c, "residential")
            lat, lon = _geo_jitter(rng, c)
            _row(w, start + pd.Timedelta(days=d, hours=float(rng.uniform(0, 24))), "signup",
                 f"n{rng.integers(1e9)}", ip, asn, lat, lon, f"fp{rng.integers(1, 2**40):010x}",
                 str(rng.choice(BENIGN_UA)))


def _attacker_ips(w, pool, n, kinds=("hosting",), countries=None):
    countries = countries or ["NL", "RU", "VN", "US", "SG", "DE"]
    out = []
    for _ in range(n):
        c = str(w.rng.choice(countries)); k = str(w.rng.choice(kinds))
        ip, asn = pool.ip(c, k)
        lat, lon = _geo_jitter(w.rng, c)
        out.append((ip, asn, lat, lon))
    return out


def _takeover_actions(w, ts, account, ip, asn, lat, lon, fp, ua, label, attack):
    rng = w.rng
    t = ts + pd.Timedelta(minutes=float(rng.uniform(2, 25)))
    _row(w, t, "mfa_change", account, ip, asn, lat, lon, fp, ua, label=label, attack=attack)
    _row(w, t + pd.Timedelta(minutes=float(rng.uniform(1, 10))), "email_change", account, ip, asn, lat, lon, fp, ua, label=label, attack=attack)
    _row(w, t + pd.Timedelta(minutes=float(rng.uniform(5, 30))), "device_pair", account, ip, asn, lat, lon, fp, ua,
         device_id=f"dx{rng.integers(1e9)}", label=label, attack=attack)


def inject_credential_stuffing(w, pool, cfg, label, day, hours, n_targets, n_ips, kinds, attempts_per_ip_hour=None):
    rng, start = w.rng, pd.Timestamp(cfg.start, tz="UTC")
    attack = "credential_stuffing"
    t0 = start + pd.Timedelta(days=day, hours=float(rng.uniform(0, 12)))
    ips = _attacker_ips(w, pool, n_ips, kinds)
    real = list(rng.choice(w.accounts.account_id, size=n_targets, replace=False))
    fake = [f"u{rng.integers(1e9)}" for _ in range(n_targets // 3)]  # usernames that do not exist
    targets = real + fake
    rng.shuffle(targets)
    acc = w.accounts.set_index("account_id")
    compromised = []
    for i, tgt in enumerate(targets):
        ts = t0 + pd.Timedelta(hours=float(rng.uniform(0, hours)))
        ip, asn, lat, lon = ips[i % n_ips] if attempts_per_ip_hour is None else ips[int(rng.integers(n_ips))]
        ua = str(rng.choice(ATTACK_UA)); fp = f"fp{rng.integers(1, 2**40):010x}"
        hit = tgt in acc.index and bool(acc.loc[tgt, "reused_pw"])
        pw = pw_hash(acc.loc[tgt, "password"]) if hit else pw_hash(f"leaked-{tgt}")
        _row(w, ts, "login", tgt, ip, asn, lat, lon, fp, ua, hit, pw, status=200 if hit else 401, label=label, attack=attack)
        if hit:
            compromised.append(tgt)
            _takeover_actions(w, ts, tgt, ip, asn, lat, lon, fp, ua, label, "account_takeover")
    w.campaigns.append(dict(label=label, attack=attack, start=t0, ips=n_ips, targets=len(targets),
                            compromised=len(compromised), variant="evasive" if attempts_per_ip_hour else "burst"))


def inject_password_spray(w, pool, cfg, label, day, n_targets=1500):
    rng, start = w.rng, pd.Timestamp(cfg.start, tz="UTC")
    t0 = start + pd.Timedelta(days=day, hours=float(rng.uniform(0, 12)))
    ips = _attacker_ips(w, pool, 25, ("hosting", "residential"))
    targets = rng.choice(w.accounts.account_id, size=n_targets, replace=False)
    common = pw_hash("Autumn2026!")
    for i, tgt in enumerate(targets):
        ip, asn, lat, lon = ips[i % len(ips)]
        ts = t0 + pd.Timedelta(hours=float(rng.uniform(0, 8)))
        _row(w, ts, "login", str(tgt), ip, asn, lat, lon, f"fp{rng.integers(1, 2**40):010x}", str(rng.choice(ATTACK_UA)),
             False, common, status=401, label=label, attack="password_spray")
    w.campaigns.append(dict(label=label, attack="password_spray", start=t0, ips=25, targets=n_targets, compromised=0, variant="slow"))


def inject_phished_takeovers(w, pool, cfg, label, day, n):
    """Correct password on the first try from a new network and device, then
    account manipulation. No failure burst, so volume rules cannot see it."""
    rng, start = w.rng, pd.Timestamp(cfg.start, tz="UTC")
    acc = w.accounts.set_index("account_id")
    victims = rng.choice(w.accounts.account_id, size=n, replace=False)
    for v in victims:
        t0 = start + pd.Timedelta(days=day + float(rng.uniform(0, 3)))
        kind = "residential" if rng.random() < 0.5 else "hosting"
        ip, asn, lat, lon = _attacker_ips(w, pool, 1, (kind,))[0]
        fp = f"fp{rng.integers(1, 2**40):010x}"; ua = "Mozilla/5.0 Chrome/129"
        _row(w, t0, "login", str(v), ip, asn, lat, lon, fp, ua, True, pw_hash(acc.loc[v, "password"]), label=label, attack="account_takeover")
        _takeover_actions(w, t0, str(v), ip, asn, lat, lon, fp, ua, label, "account_takeover")
    w.campaigns.append(dict(label=label, attack="account_takeover", start=start + pd.Timedelta(days=day), ips=n, targets=n, compromised=n, variant="phished"))


def inject_device_clone(w, pool, cfg, label, day, n):
    rng, start = w.rng, pd.Timestamp(cfg.start, tz="UTC")
    devs = w.devices.sample(n, random_state=int(rng.integers(1e6)))
    for dv in devs.itertuples():
        ip, asn, lat, lon = _attacker_ips(w, pool, 1, ("hosting",))[0]
        t0 = start + pd.Timedelta(days=day, hours=float(rng.uniform(0, 24)))
        for k in range(int(rng.integers(8, 20))):
            _row(w, t0 + pd.Timedelta(hours=k * 4 + float(rng.normal(0, .1))), "device_checkin", dv.account_id, ip, asn, lat, lon,
                 device_id=dv.device_id, ua="DeviceAgent/3.4", endpoint="POST /v1/checkin", label=label, attack="device_clone")
    w.campaigns.append(dict(label=label, attack="device_clone", start=start + pd.Timedelta(days=day), ips=n, targets=n, compromised=n, variant="cloned_serial"))


def inject_enumeration(w, pool, cfg, label, day):
    rng, start = w.rng, pd.Timestamp(cfg.start, tz="UTC")
    for k in range(3):
        a = str(rng.choice(w.accounts.account_id))
        ip, asn, lat, lon = _attacker_ips(w, pool, 1)[0]
        t0 = start + pd.Timedelta(days=day + k, hours=float(rng.uniform(0, 24)))
        base = int(rng.integers(0, 500000))
        for j in range(int(rng.integers(400, 900))):
            did = f"d{base + j:06d}"
            _row(w, t0 + pd.Timedelta(seconds=j * float(rng.uniform(0.3, 1.5))), "api_call", a, ip, asn, lat, lon,
                 "fpbot", "python-requests/2.32", status=404 if rng.random() < 0.9 else 403, device_id=did,
                 endpoint="GET /v1/devices/{id}", label=label, attack="api_enumeration")
    w.campaigns.append(dict(label=label, attack="api_enumeration", start=start + pd.Timedelta(days=day), ips=3, targets=3, compromised=0, variant="sequential_ids"))


def inject_fake_account_ring(w, pool, cfg, label, day):
    rng, start = w.rng, pd.Timestamp(cfg.start, tz="UTC")
    fps = [f"fp{rng.integers(1, 2**40):010x}" for _ in range(6)]
    ips = _attacker_ips(w, pool, 10, ("residential", "mobile"), ["US", "IN", "BR", "VN"])
    for _i in range(120):
        ip, asn, lat, lon = ips[int(rng.integers(len(ips)))]
        ts = start + pd.Timedelta(days=day + float(rng.uniform(0, 5)))
        acct = f"n{rng.integers(1e9)}"
        fp = fps[int(rng.integers(len(fps)))]
        _row(w, ts, "signup", acct, ip, asn, lat, lon, fp, "HomeApp/5.2 Android", label=label, attack="fake_account_ring")
        _row(w, ts + pd.Timedelta(minutes=float(rng.uniform(1, 20))), "referral_claim", acct, ip, asn, lat, lon, fp,
             "HomeApp/5.2 Android", endpoint="POST /v1/promo/redeem", label=label, attack="fake_account_ring")
    w.campaigns.append(dict(label=label, attack="fake_account_ring", start=start + pd.Timedelta(days=day), ips=10, targets=120, compromised=0, variant="shared_fingerprints"))


COLUMNS = ["ts", "event_type", "account_id", "ip", "asn", "lat", "lon", "device_fp", "user_agent",
           "success", "pw_hash", "device_id", "endpoint", "status", "label", "attack"]


def generate(cfg: Config | None = None) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Returns (events, campaigns, asns). Days 0-9 are the training window and
    days 10+ the test window; every attack type appears in both, and the test
    window adds evasive variants never seen in training."""
    cfg = cfg or Config()
    w, pool = build_world(cfg)
    simulate_benign(w, pool, cfg)
    k = cfg.accounts / 4000  # campaign sizes scale with the population (small configs for tests)
    n = lambda x: max(3, int(round(x * k)))
    # training window
    inject_credential_stuffing(w, pool, cfg, "C01", 2, 4, n(600), max(2, n(120)), ("hosting",))
    inject_password_spray(w, pool, cfg, "C02", 4, n(1500))
    inject_phished_takeovers(w, pool, cfg, "C03", 5, n(12))
    inject_device_clone(w, pool, cfg, "C04", 6, n(8))
    inject_enumeration(w, pool, cfg, "C05", 7)
    inject_fake_account_ring(w, pool, cfg, "C06", 3)
    # test window, including evasive variants
    inject_credential_stuffing(w, pool, cfg, "C11", 12, 3, n(700), max(2, n(150)), ("hosting",))
    inject_credential_stuffing(w, pool, cfg, "C12", 14, 60, n(500), max(2, n(400)), ("residential", "mobile"), attempts_per_ip_hour=1)
    inject_password_spray(w, pool, cfg, "C13", 16, n(1500))
    inject_phished_takeovers(w, pool, cfg, "C14", 13, n(15))
    inject_device_clone(w, pool, cfg, "C15", 17, n(10))
    inject_enumeration(w, pool, cfg, "C16", 15)
    inject_fake_account_ring(w, pool, cfg, "C17", 15)
    ev = pd.DataFrame(w.rows, columns=COLUMNS).sort_values("ts", kind="stable").reset_index(drop=True)
    ev.insert(0, "event_id", np.arange(len(ev), dtype=np.int64))
    ev["country"] = ev["asn"].map(w.asns.set_index("asn")["country"])
    ev["asn_type"] = ev["asn"].map(w.asns.set_index("asn")["asn_type"])
    return ev, pd.DataFrame(w.campaigns), w.asns.drop(columns="ip_base")
