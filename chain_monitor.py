"""Chain Monitor - monitor on-chain contracts with notifications on update.
Supports Proxy Upgrade detection by comparing bytecode hash."""
import os
import json
import time
import hashlib
import logging
import threading
from typing import Optional, Callable

logger = logging.getLogger(__name__)

MONITOR_FILE = os.path.join(os.path.dirname(__file__), "monitor_state.json")


class MonitoredContract:
    def __init__(self, address: str, chain: str = "ethereum", interval: int = 3600,
                 api_key: str = "", label: str = ""):
        self.address = address
        self.chain = chain
        self.interval = interval
        self.api_key = api_key
        self.label = label or address[:10]
        # Two independent baselines (M17 remediation): check() tracks the
        # SOURCE hash while check_for_upgrade() tracks the (truncated)
        # BYTECODE hash. Sharing one last_hash across both domains made a
        # false proxy-upgrade alert fire on every cycle.
        self.last_source_hash = ""
        self.last_bytecode_hash = ""
        self.last_seen = 0

    def to_dict(self, redact: bool = True) -> dict:
        """Serialize for output. Explorer keys are stripped by default
        (M12 remediation): list()/API responses never carry secrets."""
        d = {
            "address": self.address, "chain": self.chain,
            "interval": self.interval,
            "label": self.label,
            "last_source_hash": self.last_source_hash,
            "last_bytecode_hash": self.last_bytecode_hash,
            "last_seen": self.last_seen,
        }
        if not redact:
            d["api_key"] = self.api_key
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "MonitoredContract":
        mc = cls(d["address"], d.get("chain", "ethereum"),
                  d.get("interval", 3600), d.get("api_key", ""),
                  d.get("label", ""))
        mc.last_source_hash = d.get("last_source_hash", "")
        mc.last_bytecode_hash = d.get("last_bytecode_hash", "")
        # Legacy single-hash state: the length tells which domain it came
        # from (check() stored 64 hex chars, check_for_upgrade() stored 16).
        legacy = d.get("last_hash", "")
        if legacy and not (mc.last_source_hash or mc.last_bytecode_hash):
            if len(legacy) == 16:
                mc.last_bytecode_hash = legacy
            else:
                mc.last_source_hash = legacy
        mc.last_seen = d.get("last_seen", 0)
        return mc


class ChainMonitor:
    """Monitor contracts on chain — checks for code changes."""

    def __init__(self, state_file: str = MONITOR_FILE):
        self.state_file = state_file
        self.contracts: list[MonitoredContract] = []
        # One lock guards the contracts list AND persistence (M18
        # remediation): the background thread iterates while request
        # threads add/remove — unsynchronized mutation raised
        # "list changed size during iteration" and could drop contracts
        # from the state file.
        self._lock = threading.RLock()
        self._load()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_change: Optional[Callable] = None

    def _load(self):
        if os.path.isfile(self.state_file):
            try:
                with open(self.state_file, encoding="utf-8") as f:
                    data = json.load(f)
                self.contracts = [MonitoredContract.from_dict(d) for d in data]
            except Exception as e:
                logger.warning(f"Failed to load monitor state: {e}")

    def _save(self):
        """Persist state; caller must hold self._lock. The file keeps the
        explorer keys but is written with 0600 permissions (M12 remediation)
        so backups/logs of the project source cannot expose them."""
        fd = os.open(self.state_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump([c.to_dict(redact=False) for c in self.contracts], f, indent=2)

    def add(self, address: str, chain: str = "ethereum", interval: int = 3600,
            api_key: str = "", label: str = ""):
        mc = MonitoredContract(address, chain, interval, api_key, label)
        with self._lock:
            self.contracts.append(mc)
            self._save()
        logger.info(f"Monitoring {address} on {chain}")

    def remove(self, address: str):
        with self._lock:
            self.contracts = [c for c in self.contracts if c.address != address]
            self._save()

    def list(self) -> list:
        with self._lock:
            return [c.to_dict() for c in self.contracts]

    def on_change(self, callback: Callable):
        """Set a callback function for when a contract changes."""
        self._on_change = callback

    def check(self):
        """Check all contracts for changes."""
        from chain_loader import load_from_explorer

        # Iterate over a snapshot so concurrent add/remove cannot corrupt
        # the loop (M18 remediation); network calls run outside the lock.
        with self._lock:
            targets = list(self.contracts)
        for mc in targets:
            if time.time() - mc.last_seen < mc.interval:
                continue
            try:
                data = load_from_explorer(mc.address, mc.chain, mc.api_key)
                if not data:
                    continue
                new_hash = hashlib.sha256(data["code"].encode()).hexdigest()
                if mc.last_source_hash and mc.last_source_hash != new_hash:
                    logger.warning(f"⚠️ Contract changed: {mc.label} ({mc.address})")
                    if self._on_change:
                        self._on_change(mc, data["code"])
                mc.last_source_hash = new_hash
                mc.last_seen = time.time()
            except Exception as e:
                logger.warning(f"Check failed for {mc.address}: {e}")
        with self._lock:
            self._save()

    def fetch_bytecode_hash(self, contract: MonitoredContract) -> Optional[str]:
        import requests
        explorer = {"ethereum": "api.etherscan.io", "bsc": "api.bscscan.com",
                    "polygon": "api.polygonscan.com", "arbitrum": "api.arbiscan.io"}
        domain = explorer.get(contract.chain, "api.etherscan.io")
        url = f"https://{domain}/api?module=proxy&action=eth_getCode&address={contract.address}&apikey={contract.api_key}"
        try:
            resp = requests.get(url, timeout=15)
            data = resp.json()
            bytecode = data.get("result", "")
            if not bytecode or bytecode == "0x":
                return None
            return hashlib.sha256(bytecode.encode()).hexdigest()[:16]
        except Exception as e:
            logger.debug(f"Bytecode fetch failed for {contract.address}: {e}")
            return None

    def check_for_upgrade(self, contract: MonitoredContract) -> Optional[str]:
        current_hash = self.fetch_bytecode_hash(contract)
        if current_hash is None:
            return None
        # Bytecode baseline is compared only against its own domain
        # (M17 remediation): sharing last_hash with the source-based
        # check() guaranteed a false upgrade alert every cycle.
        with self._lock:
            if contract.last_bytecode_hash and contract.last_bytecode_hash != current_hash:
                old_hash = contract.last_bytecode_hash
                contract.last_bytecode_hash = current_hash
                contract.last_seen = time.time()
                self._save()
                return (f"⚠️ *Proxy Upgrade Detected*\n"
                        f"Contract: `{contract.address}` ({contract.label})\n"
                        f"Bytecode hash: `{old_hash[:8]} → {current_hash[:8]}`\n"
                        f"Chain: {contract.chain}\nTriggering re-audit...")
            if not contract.last_bytecode_hash:
                contract.last_bytecode_hash = current_hash
            contract.last_seen = time.time()
        return None

    def start(self, interval: int = 60):
        """Start periodic monitoring in background."""
        if self._running:
            return
        self._running = True

        def loop():
            while self._running:
                self.check()
                time.sleep(interval)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        logger.info("Chain monitor started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)


_MONITOR = ChainMonitor()


def get_monitor() -> ChainMonitor:
    return _MONITOR
