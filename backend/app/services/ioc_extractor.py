"""IOC extraction from structured Incident/Alert/Event evidence.

Security constraints:
- Only inspects approved structured fields (source_ip, destination_ip, event metadata).
- Never extracts credentials, API keys, passwords, tokens, cookies, or auth headers.
- Validates and normalizes all extracted indicators.
- Deduplicates by (ioc_type, normalized_value).
- Bounds all IOC values.
"""

import hashlib
import ipaddress
import logging
import re
from datetime import datetime

from ..models.threat_intel import IOC, IOCType

logger = logging.getLogger(__name__)

# Maximum lengths for security bounding
_MAX_IOC_VALUE_LEN = 2048
_MAX_DOMAIN_LEN = 253
_MAX_URL_LEN = 2048

# Patterns for credential-like strings that must NEVER be extracted as IOCs
_CREDENTIAL_PATTERNS = re.compile(
    r"(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"session[_-]?cookie|bearer|authorization|x-api-key|private[_-]?key)",
    re.IGNORECASE,
)

# Compiled validation patterns
_DOMAIN_PATTERN = re.compile(
    r"^(?!-)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)
_SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
_SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
_MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
_URL_PATTERN = re.compile(r"^https?://[^\s]{1,2000}$", re.IGNORECASE)


def _is_credential_like(value: str) -> bool:
    """Check if a string looks like a credential or secret."""
    return bool(_CREDENTIAL_PATTERNS.search(value))


def _validate_ipv4(value: str) -> str | None:
    """Validate and normalize an IPv4 address. Returns normalized string or None."""
    try:
        addr = ipaddress.IPv4Address(value.strip())
        return str(addr)
    except (ipaddress.AddressValueError, ValueError):
        return None


def _validate_ipv6(value: str) -> str | None:
    """Validate and normalize an IPv6 address. Returns normalized string or None."""
    try:
        addr = ipaddress.IPv6Address(value.strip())
        return str(addr)
    except (ipaddress.AddressValueError, ValueError):
        return None


def _validate_domain(value: str) -> str | None:
    """Validate and normalize a domain name. Returns normalized string or None."""
    cleaned = value.strip().lower().rstrip(".")
    if not cleaned or len(cleaned) > _MAX_DOMAIN_LEN:
        return None
    if _DOMAIN_PATTERN.match(cleaned):
        return cleaned
    return None


def _validate_url(value: str) -> str | None:
    """Validate and normalize a URL. Returns normalized string or None."""
    cleaned = value.strip()
    if not cleaned or len(cleaned) > _MAX_URL_LEN:
        return None
    if _URL_PATTERN.match(cleaned):
        return cleaned
    return None


def _validate_hash(value: str, hash_type: IOCType) -> str | None:
    """Validate and normalize a file hash. Returns uppercase normalized string or None."""
    cleaned = value.strip()
    if hash_type == IOCType.SHA256 and _SHA256_PATTERN.match(cleaned):
        return cleaned.upper()
    if hash_type == IOCType.SHA1 and _SHA1_PATTERN.match(cleaned):
        return cleaned.upper()
    if hash_type == IOCType.MD5 and _MD5_PATTERN.match(cleaned):
        return cleaned.upper()
    return None


def _generate_ioc_id(ioc_type: IOCType, normalized_value: str) -> str:
    """Generate deterministic IOC identifier from type + normalized value."""
    digest = hashlib.sha256(f"ioc:{ioc_type.value}:{normalized_value}".encode()).hexdigest()[:16]
    return f"ioc-{digest}"


def _try_extract_ip(value: str) -> tuple[IOCType, str] | None:
    """Try to parse a string as IPv4 or IPv6."""
    normalized = _validate_ipv4(value)
    if normalized:
        return (IOCType.IPV4, normalized)
    normalized = _validate_ipv6(value)
    if normalized:
        return (IOCType.IPV6, normalized)
    return None


class IOCExtractor:
    """Extracts IOCs from structured Incident/Alert/Event evidence.

    Only inspects approved fields. Never extracts credentials.
    """

    # Approved metadata keys to scan for IOCs
    APPROVED_METADATA_KEYS = frozenset({
        "domain", "url", "file_hash", "file_sha256", "file_sha1", "file_md5",
        "src_ip", "dst_ip", "source_ip", "destination_ip", "dest_ip",
        "hostname", "target_domain", "target_url",
    })

    # Metadata keys that indicate hash types
    HASH_KEYS = frozenset({
        "file_hash", "file_sha256", "file_sha1", "file_md5",
    })

    def extract_from_event_data(
        self,
        *,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        metadata: dict | None = None,
        source_context: str = "event",
        timestamp: datetime | None = None,
    ) -> list[IOC]:
        """Extract IOCs from structured event fields.

        Args:
            source_ip: Event source IP field.
            destination_ip: Event destination IP field.
            metadata: Event metadata dict (only approved keys are scanned).
            source_context: Context label for where the IOC came from.
            timestamp: Timestamp for first_seen/last_seen.

        Returns:
            Deduplicated list of validated IOC objects.
        """
        seen: dict[tuple[str, str], IOC] = {}

        # Extract from source_ip field
        if source_ip and not _is_credential_like(source_ip):
            self._try_add_ip(source_ip, f"{source_context}:source_ip", timestamp, seen)

        # Extract from destination_ip field
        if destination_ip and not _is_credential_like(destination_ip):
            self._try_add_ip(destination_ip, f"{source_context}:destination_ip", timestamp, seen)

        # Extract from approved metadata keys only
        if metadata:
            for key, value in metadata.items():
                if key not in self.APPROVED_METADATA_KEYS:
                    continue
                if not isinstance(value, str) or not value.strip():
                    continue
                if len(value) > _MAX_IOC_VALUE_LEN:
                    continue
                if _is_credential_like(value) or _is_credential_like(key):
                    continue

                ctx = f"{source_context}:metadata:{key}"
                self._try_add_indicator(value, key, ctx, timestamp, seen)

        return list(seen.values())

    def extract_from_incident(
        self,
        *,
        incident_evidence: dict | None = None,
        alert_evidences: list[dict] | None = None,
        event_data: list[dict] | None = None,
        source_context: str = "incident",
        timestamp: datetime | None = None,
    ) -> list[IOC]:
        """Extract IOCs from all structured evidence associated with an incident.

        Args:
            incident_evidence: Incident.evidence dict.
            alert_evidences: List of Alert.evidence dicts.
            event_data: List of dicts with source_ip, destination_ip, metadata keys.
            source_context: Context label.
            timestamp: Timestamp for first_seen/last_seen.

        Returns:
            Deduplicated list of validated IOC objects.
        """
        seen: dict[tuple[str, str], IOC] = {}

        # Extract from event data (most granular source)
        if event_data:
            for i, ev in enumerate(event_data):
                src_ip = ev.get("source_ip")
                dst_ip = ev.get("destination_ip")
                meta = ev.get("metadata", {})
                ctx = f"{source_context}:event:{i}"
                if src_ip and isinstance(src_ip, str) and not _is_credential_like(src_ip):
                    self._try_add_ip(src_ip, f"{ctx}:source_ip", timestamp, seen)
                if dst_ip and isinstance(dst_ip, str) and not _is_credential_like(dst_ip):
                    self._try_add_ip(dst_ip, f"{ctx}:destination_ip", timestamp, seen)
                if isinstance(meta, dict):
                    for key, value in meta.items():
                        if key not in self.APPROVED_METADATA_KEYS:
                            continue
                        if not isinstance(value, str) or not value.strip():
                            continue
                        if len(value) > _MAX_IOC_VALUE_LEN:
                            continue
                        if _is_credential_like(value) or _is_credential_like(key):
                            continue
                        self._try_add_indicator(value, key, f"{ctx}:metadata:{key}", timestamp, seen)

        # Extract from alert evidence (approved keys)
        if alert_evidences:
            for i, evidence in enumerate(alert_evidences):
                if not isinstance(evidence, dict):
                    continue
                ctx = f"{source_context}:alert:{i}"
                for key, value in evidence.items():
                    if key not in self.APPROVED_METADATA_KEYS:
                        continue
                    if not isinstance(value, str) or not value.strip():
                        continue
                    if len(value) > _MAX_IOC_VALUE_LEN:
                        continue
                    if _is_credential_like(value) or _is_credential_like(key):
                        continue
                    self._try_add_indicator(value, key, f"{ctx}:{key}", timestamp, seen)

        return list(seen.values())

    def _try_add_ip(
        self,
        value: str,
        context: str,
        timestamp: datetime | None,
        seen: dict[tuple[str, str], IOC],
    ) -> None:
        """Try to validate and add an IP address IOC."""
        result = _try_extract_ip(value)
        if result:
            ioc_type, normalized = result
            key = (ioc_type.value, normalized)
            if key not in seen:
                seen[key] = IOC(
                    ioc_id=_generate_ioc_id(ioc_type, normalized),
                    ioc_type=ioc_type,
                    value=value.strip(),
                    normalized_value=normalized,
                    source_context=context,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )

    def _try_add_indicator(
        self,
        value: str,
        key_hint: str,
        context: str,
        timestamp: datetime | None,
        seen: dict[tuple[str, str], IOC],
    ) -> None:
        """Try to validate and add an indicator based on its metadata key hint and value."""
        # IP fields
        if key_hint in ("src_ip", "dst_ip", "source_ip", "destination_ip", "dest_ip"):
            self._try_add_ip(value, context, timestamp, seen)
            return

        # Domain fields
        if key_hint in ("domain", "hostname", "target_domain"):
            normalized = _validate_domain(value)
            if normalized:
                dedup_key = (IOCType.DOMAIN.value, normalized)
                if dedup_key not in seen:
                    seen[dedup_key] = IOC(
                        ioc_id=_generate_ioc_id(IOCType.DOMAIN, normalized),
                        ioc_type=IOCType.DOMAIN,
                        value=value.strip(),
                        normalized_value=normalized,
                        source_context=context,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
            return

        # URL fields
        if key_hint in ("url", "target_url"):
            normalized = _validate_url(value)
            if normalized:
                dedup_key = (IOCType.URL.value, normalized)
                if dedup_key not in seen:
                    seen[dedup_key] = IOC(
                        ioc_id=_generate_ioc_id(IOCType.URL, normalized),
                        ioc_type=IOCType.URL,
                        value=value.strip(),
                        normalized_value=normalized,
                        source_context=context,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
            return

        # Hash fields — try SHA256 first, then SHA1, then MD5
        if key_hint in self.HASH_KEYS:
            for hash_type in (IOCType.SHA256, IOCType.SHA1, IOCType.MD5):
                normalized = _validate_hash(value, hash_type)
                if normalized:
                    dedup_key = (hash_type.value, normalized)
                    if dedup_key not in seen:
                        seen[dedup_key] = IOC(
                            ioc_id=_generate_ioc_id(hash_type, normalized),
                            ioc_type=hash_type,
                            value=value.strip(),
                            normalized_value=normalized,
                            source_context=context,
                            first_seen=timestamp,
                            last_seen=timestamp,
                        )
                    return
