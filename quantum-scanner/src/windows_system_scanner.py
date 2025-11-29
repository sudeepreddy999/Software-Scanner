

from __future__ import annotations

import os
import sys
import platform
from typing import List, Optional, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
    from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
    from cryptography.hazmat.backends import default_backend
except Exception:  
    x509 = None  

from .scanner import ScanResult, Finding
from .vulnerability_db import VulnerabilityDatabase, Severity


class WindowsSystemScanner:
    """Scanner for Windows static system files."""

    DEFAULT_DIRS = [
        r"C:\\ProgramData",
        r"C:\\Program Files",
        r"C:\\Program Files (x86)",
        r"C:\\Windows\\System32",
        r"C:\\Users",
    ]

    FILE_EXTS = {".pem", ".crt", ".cer", ".der", ".pfx", ".p12", ".key", ".pub", ".cfg", ".conf", ".ini"}
    SSH_FILENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts", "authorized_keys"}

    def __init__(self, paths: Optional[List[str]] = None):
        self.paths = paths or self.DEFAULT_DIRS
        self.vuln_db = VulnerabilityDatabase()

    def scan(self, verbose: bool = False) -> ScanResult:
        result = ScanResult()

        if platform.system() != "Windows":
            result.add_error("system", "Windows system scan is only supported on Windows hosts.")
            return result

        if x509 is None:
            result.add_error("dependencies", "Python 'cryptography' package is required for system scan.")
            return result

        files = self._discover_files(self.paths)
        result.files_scanned = len(files)

        for fp in files:
            try:
                # Decide how to parse based on extension/name
                finding = self._analyze_file(fp)
                if finding:
                    result.add_finding(finding)
            except Exception as e:  # be resilient
                result.add_error(fp, str(e))

        # Keep same sorting as main scanner
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.SAFE: 4,
        }
        result.findings.sort(key=lambda f: (severity_order[f.severity], f.file_path, f.line_number))
        return result

    def _discover_files(self, roots: List[str]) -> List[str]:
        out: List[str] = []
        for root in roots:
            if not os.path.exists(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                # Skip obvious huge dirs to keep runtime reasonable
                base = os.path.basename(dirpath).lower()
                if base in {"winsxs", "system volume information", "$recycle.bin", "appdata"}:
                    continue
                for fn in filenames:
                    ext = os.path.splitext(fn)[1].lower()
                    if ext in self.FILE_EXTS or fn in self.SSH_FILENAMES:
                        out.append(os.path.join(dirpath, fn))
        return out

    def _analyze_file(self, path: str) -> Optional[Finding]:
        ext = os.path.splitext(path)[1].lower()
        name = os.path.basename(path).lower()

        # SSH private keys by filename
        if name in {"id_rsa", "id_dsa", "id_ecdsa"}:
            alg = {
                "id_rsa": "RSA",
                "id_dsa": "DSA",
                "id_ecdsa": "ECDSA",
            }[name]
            key_size = self._try_load_pem_private_key_for_size(path)
            return self._make_finding(path, alg, key_size, matched="ssh private key")

        # Certificate/Key containers
        if ext in {".pem", ".crt", ".cer", ".der"}:
            alg, key_size = self._parse_certificate_file(path)
            if alg:
                return self._make_finding(path, alg, key_size, matched="x509 certificate")

        if ext in {".key", ".p12", ".pfx"}:
            alg, key_size = self._parse_key_container(path)
            if alg:
                return self._make_finding(path, alg, key_size, matched="key container")

        if ext in {".cfg", ".conf", ".ini"} or name.endswith(".config"):
            # Scan config text for algorithms and key sizes
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                text = ""
            alg, key_size = self._scan_text_for_alg_and_size(text)
            if alg:
                return self._make_finding(path, alg, key_size, matched="config reference")

        # PEM encoded private keys
        if ext == ".pem" and os.path.exists(path):
            key_size = self._try_load_pem_private_key_for_size(path)
            if key_size:
                return self._make_finding(path, "RSA", key_size, matched="pem key")  # default to RSA if parsed

        return None

    def _parse_certificate_file(self, path: str) -> Tuple[Optional[str], Optional[int]]:
        try:
            with open(path, "rb") as f:
                data = f.read()
            # Try PEM then DER
            cert = None
            try:
                cert = x509.load_pem_x509_certificate(data)
            except Exception:
                cert = x509.load_der_x509_certificate(data)
            pub = cert.public_key()  # type: ignore
            if isinstance(pub, rsa.RSAPublicKey):
                return "RSA", pub.key_size
            if isinstance(pub, dsa.DSAPublicKey):
                return "DSA", pub.key_size
            if isinstance(pub, ec.EllipticCurvePublicKey):
                # ECDSA key size corresponds to curve size
                try:
                    size = pub.curve.key_size  # type: ignore[attr-defined]
                except Exception:
                    size = None
                return "ECDSA", size
        except Exception:
            pass
        return None, None

    def _parse_key_container(self, path: str) -> Tuple[Optional[str], Optional[int]]:
        ext = os.path.splitext(path)[1].lower()
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            return None, None
        # PKCS#12
        if ext in {".p12", ".pfx"}:
            try:
                key, cert, _ = load_key_and_certificates(data, password=None)
                if key is not None:
                    if hasattr(key, "key_size"):
                        return "RSA", getattr(key, "key_size", None)
                if cert is not None:
                    alg, size = self._public_key_info(cert)
                    return alg, size
            except Exception:
                # Encrypted or unsupported
                return None, None
        # .key might be PEM
        if ext == ".key":
            ks = self._try_load_pem_private_key_for_size(path)
            if ks:
                return "RSA", ks
        return None, None

    def _public_key_info(self, cert) -> Tuple[Optional[str], Optional[int]]:
        try:
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                return "RSA", pub.key_size
            if isinstance(pub, dsa.DSAPublicKey):
                return "DSA", pub.key_size
            if isinstance(pub, ec.EllipticCurvePublicKey):
                try:
                    size = pub.curve.key_size
                except Exception:
                    size = None
                return "ECDSA", size
        except Exception:
            pass
        return None, None

    def _try_load_pem_private_key_for_size(self, path: str) -> Optional[int]:
        try:
            with open(path, "rb") as f:
                data = f.read()
            key = serialization.load_pem_private_key(data, password=None)
            if hasattr(key, "key_size"):
                return int(getattr(key, "key_size"))
        except Exception:
            return None
        return None

    def _scan_text_for_alg_and_size(self, text: str) -> Tuple[Optional[str], Optional[int]]:
        import re
        # Look for algorithm names
        algs = ["RSA", "ECDSA", "DSA", "Diffie-Hellman", "DH", "EC"]
        found_alg = None
        for a in algs:
            if re.search(rf"\b{re.escape(a)}\b", text, flags=re.IGNORECASE):
                # Normalize
                found_alg = "ECDSA" if a in ("EC", "ECDSA") else ("Diffie-Hellman" if a == "DH" else a)
                break
        # Extract size
        key_size = None
        size_matchers = [
            r"\b(\d{3,5})\s*-?\s*bits?\b",
            r"modulusLength\s*[:=]\s*(\d{3,5})",
            r"key[_-]?size\s*[:=]\s*(\d{3,5})",
            r"initialize\s*\(\s*(\d{3,5})\s*\)",
        ]
        for pat in size_matchers:
            m = re.search(pat, text, flags=re.IGNORECASE)
            if m:
                try:
                    key_size = int(m.group(1))
                    break
                except Exception:
                    pass
        return found_alg, key_size

    def _make_finding(self, path: str, algorithm: str, key_size: Optional[int], matched: str) -> Finding:
        # Map algorithm to DB signature and adjust severity based on key size
        sig = self.vuln_db.get_signature_by_algorithm(algorithm)
        severity = self.vuln_db.get_severity_for_algorithm_and_size(algorithm, key_size)
        description = (sig.description if sig else f"{algorithm} usage detected on system.")
        recommendation = (sig.recommendation if sig else "Migrate to post-quantum alternatives (Kyber/Dilithium).")
        confidence = "high" if key_size else "low"
        return Finding(
            file_path=path,
            line_number=0,
            algorithm=algorithm,
            severity=severity,
            matched_pattern=matched,
            line_content="",
            description=description,
            recommendation=recommendation,
            key_size=key_size,
            confidence=confidence,
        )
