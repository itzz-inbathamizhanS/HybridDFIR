"""
connection_scanner.py - Zero-Dependency Live Network Connection Inspector
=========================================================================

Enumerates all active TCP and UDP connections on the local system using
the Win32 ``iphlpapi.dll`` API (``GetExtendedTcpTable`` /
``GetExtendedUdpTable``), maps each connection to its owning process,
and flags suspicious network activity using heuristic rules.

Capabilities
------------
* Full TCP/UDP connection enumeration with owning PID resolution
* C2 beacon port detection (Cobalt Strike, Metasploit, Empire defaults)
* Suspicious process-to-network mapping (system processes shouldn't connect out)
* Data exfiltration pattern detection (high-port outbound from unexpected processes)
* MITRE ATT&CK TTP mapping for network-based indicators
* Structured dict/JSON output compatible with the correlation pipeline

Usage
-----
    from src.network.connection_scanner import NetworkConnectionScanner

    scanner = NetworkConnectionScanner()
    findings = scanner.scan_connections()
    scanner.display_findings(findings)
"""

from __future__ import annotations

import ctypes
import datetime
import logging
import socket
import struct
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
#  Win32 Constants for iphlpapi
# ---------------------------------------------------------------------------
AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

# TCP connection states
_TCP_STATES = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RCVD",
    5: "ESTABLISHED",
    6: "FIN_WAIT1",
    7: "FIN_WAIT2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}


# ---------------------------------------------------------------------------
#  Win32 Structures
# ---------------------------------------------------------------------------

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_ulong),
        ("dwLocalAddr", ctypes.c_ulong),
        ("dwLocalPort", ctypes.c_ulong),
        ("dwRemoteAddr", ctypes.c_ulong),
        ("dwRemotePort", ctypes.c_ulong),
        ("dwOwningPid", ctypes.c_ulong),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", ctypes.c_ulong),
        ("dwLocalPort", ctypes.c_ulong),
        ("dwOwningPid", ctypes.c_ulong),
    ]


# ---------------------------------------------------------------------------
#  Threat Intelligence - Known Suspicious Ports & Patterns
# ---------------------------------------------------------------------------

# Common C2 framework default ports
C2_PORTS = frozenset({
    4444,   # Metasploit default
    5555,   # Common RAT
    8888,   # Common backdoor
    1337,   # Elite/leet port
    6666, 6667,  # IRC C2
    9999,   # Common RAT
    1234,   # Common test backdoor
    31337,  # Back Orifice
    12345,  # NetBus
    54321,  # Common reverse shell
    50050,  # Cobalt Strike default
    2222,   # Alt SSH
    4443,   # Cobalt Strike alt
    9090,   # Common management
})

# Processes that should NOT have outbound network connections
SUSPICIOUS_NETWORK_PROCESSES = frozenset({
    "lsass.exe",        # Credential store - should never connect out
    "csrss.exe",        # Client/Server Runtime - no networking
    "smss.exe",         # Session Manager - no networking
    "wininit.exe",      # Windows Init - no networking
    "services.exe",     # Service Control Manager - minimal networking
    "taskhost.exe",     # Task Host - suspicious if connecting out
    "taskhostw.exe",    # Task Host Window - same
    "dwm.exe",          # Desktop Window Manager
    "winlogon.exe",     # Logon process - no external connections
    "spoolsv.exe",      # Print Spooler - external connections suspicious
    "cmd.exe",          # Command shell - external connections very suspicious
    "powershell.exe",   # PowerShell - external connections suspicious
    "pwsh.exe",         # PowerShell Core
    "mshta.exe",        # HTML Application Host - often abused
    "rundll32.exe",     # DLL execution host - often abused
    "regsvr32.exe",     # Registry server - often abused
    "certutil.exe",     # Certificate utility - download abuse
    "bitsadmin.exe",    # BITS - download abuse
    "wscript.exe",      # Windows Script Host
    "cscript.exe",      # Console Script Host
})

# Known safe localhost / internal ranges
_LOOPBACK_PREFIXES = ("127.", "0.0.0.0", "::1")

# MITRE ATT&CK Mappings for network indicators
_NETWORK_MITRE = {
    "C2_PORT": "T1571",          # Non-Standard Port
    "C2_BEACON": "T1071.001",    # Application Layer Protocol: Web
    "SUSPICIOUS_PROCESS": "T1071",  # Application Layer Protocol
    "DATA_EXFIL": "T1041",       # Exfiltration Over C2 Channel
    "LATERAL_MOVEMENT": "T1021", # Remote Services
    "DNS_TUNNEL": "T1071.004",   # Application Layer Protocol: DNS
}


# ---------------------------------------------------------------------------
#  NetworkConnectionScanner
# ---------------------------------------------------------------------------

class NetworkConnectionScanner:
    """
    Zero-dependency live Windows network connection scanner.

    Uses iphlpapi.dll via ctypes to enumerate all TCP/UDP connections,
    map them to owning processes, and flag suspicious network behavior.
    """

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()
        try:
            self._iphlpapi = ctypes.windll.iphlpapi
            self._kernel32 = ctypes.windll.kernel32
        except Exception:
            self._iphlpapi = None
            self._kernel32 = None

    # ------------------------------------------------------------------
    #  Process name resolution cache
    # ------------------------------------------------------------------

    def _build_pid_map(self) -> Dict[int, str]:
        """Build a PID -> process name mapping using Toolhelp32 snapshot."""
        from src.capture.native_ram import (
            PROCESSENTRY32, TH32CS_SNAPPROCESS, INVALID_HANDLE_VALUE
        )

        pid_map: Dict[int, str] = {0: "System Idle", 4: "System"}

        h_snap = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if h_snap in (INVALID_HANDLE_VALUE, None, 0):
            return pid_map

        try:
            pe = PROCESSENTRY32()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

            if not self._kernel32.Process32First(h_snap, ctypes.byref(pe)):
                return pid_map

            while True:
                pid = pe.th32ProcessID
                try:
                    name = pe.szExeFile.decode("utf-8", errors="replace").rstrip("\x00")
                except Exception:
                    name = "<unknown>"
                pid_map[pid] = name
                if not self._kernel32.Process32Next(h_snap, ctypes.byref(pe)):
                    break
        finally:
            self._kernel32.CloseHandle(h_snap)

        return pid_map

    # ------------------------------------------------------------------
    #  TCP Enumeration
    # ------------------------------------------------------------------

    def _get_tcp_connections(self) -> List[Dict[str, Any]]:
        """Enumerate all TCP connections using GetExtendedTcpTable."""
        connections = []
        if not self._iphlpapi:
            return connections

        # First call to get required buffer size
        size = ctypes.c_ulong(0)
        self._iphlpapi.GetExtendedTcpTable(
            None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
        )

        buf = (ctypes.c_byte * size.value)()
        ret = self._iphlpapi.GetExtendedTcpTable(
            buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
        )

        if ret != 0:
            logger.warning("GetExtendedTcpTable failed with error code %d", ret)
            return connections

        # Parse the table: first DWORD is row count
        num_entries = struct.unpack_from("I", buf, 0)[0]
        row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
        offset = 4  # skip the dwNumEntries field

        for i in range(num_entries):
            row = MIB_TCPROW_OWNER_PID.from_buffer_copy(buf, offset)
            offset += row_size

            local_ip = socket.inet_ntoa(struct.pack("<I", row.dwLocalAddr))
            remote_ip = socket.inet_ntoa(struct.pack("<I", row.dwRemoteAddr))
            local_port = socket.ntohs(row.dwLocalPort & 0xFFFF)
            remote_port = socket.ntohs(row.dwRemotePort & 0xFFFF)

            connections.append({
                "protocol": "TCP",
                "local_addr": f"{local_ip}:{local_port}",
                "remote_addr": f"{remote_ip}:{remote_port}",
                "local_ip": local_ip,
                "remote_ip": remote_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "state": _TCP_STATES.get(row.dwState, f"UNKNOWN({row.dwState})"),
                "pid": row.dwOwningPid,
            })

        return connections

    # ------------------------------------------------------------------
    #  UDP Enumeration
    # ------------------------------------------------------------------

    def _get_udp_connections(self) -> List[Dict[str, Any]]:
        """Enumerate all UDP endpoints using GetExtendedUdpTable."""
        connections = []
        if not self._iphlpapi:
            return connections

        size = ctypes.c_ulong(0)
        self._iphlpapi.GetExtendedUdpTable(
            None, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0
        )

        buf = (ctypes.c_byte * size.value)()
        ret = self._iphlpapi.GetExtendedUdpTable(
            buf, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0
        )

        if ret != 0:
            logger.warning("GetExtendedUdpTable failed with error code %d", ret)
            return connections

        num_entries = struct.unpack_from("I", buf, 0)[0]
        row_size = ctypes.sizeof(MIB_UDPROW_OWNER_PID)
        offset = 4

        for i in range(num_entries):
            row = MIB_UDPROW_OWNER_PID.from_buffer_copy(buf, offset)
            offset += row_size

            local_ip = socket.inet_ntoa(struct.pack("<I", row.dwLocalAddr))
            local_port = socket.ntohs(row.dwLocalPort & 0xFFFF)

            connections.append({
                "protocol": "UDP",
                "local_addr": f"{local_ip}:{local_port}",
                "remote_addr": "*:*",
                "local_ip": local_ip,
                "remote_ip": "*",
                "local_port": local_port,
                "remote_port": 0,
                "state": "LISTENING",
                "pid": row.dwOwningPid,
            })

        return connections

    # ------------------------------------------------------------------
    #  Threat Analysis
    # ------------------------------------------------------------------

    def _analyze_connection(
        self, conn: Dict[str, Any], process_name: str
    ) -> Dict[str, Any]:
        """Apply heuristic rules to a single connection and return findings."""
        threat_labels = []
        risk_score = 0
        mitre_ttps = []
        remote_ip = conn["remote_ip"]
        remote_port = conn["remote_port"]
        is_outbound = conn["state"] == "ESTABLISHED" and remote_ip not in ("0.0.0.0", "*")
        is_loopback = any(remote_ip.startswith(p) for p in _LOOPBACK_PREFIXES)

        # Rule 1: C2 port detection
        if remote_port in C2_PORTS and is_outbound and not is_loopback:
            threat_labels.append(f"C2_SUSPECT_PORT_{remote_port}")
            risk_score += 75
            mitre_ttps.append(_NETWORK_MITRE["C2_PORT"])

        # Rule 2: Suspicious process with external connection
        if process_name.lower() in SUSPICIOUS_NETWORK_PROCESSES and is_outbound and not is_loopback:
            threat_labels.append(f"SUSPICIOUS_OUTBOUND_{process_name}")
            risk_score += 85
            mitre_ttps.append(_NETWORK_MITRE["SUSPICIOUS_PROCESS"])

        # Rule 3: Non-browser process using HTTPS (443)
        browser_procs = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
                         "opera.exe", "msedgewebview2.exe", "iexplore.exe"}
        if (remote_port == 443 and is_outbound and not is_loopback
                and process_name.lower() not in browser_procs
                and not process_name.lower().startswith("dell.")
                and process_name.lower() not in {"svchost.exe", "backgroundtaskhost.exe",
                                                  "searchhost.exe", "widgets.exe",
                                                  "microsoftstartfeedhost.exe"}):
            threat_labels.append("NON_BROWSER_HTTPS")
            risk_score += 40
            mitre_ttps.append(_NETWORK_MITRE["C2_BEACON"])

        # Rule 4: High port outbound from system process
        if (remote_port > 10000 and is_outbound and not is_loopback
                and process_name.lower() in SUSPICIOUS_NETWORK_PROCESSES):
            threat_labels.append("HIGH_PORT_SYSTEM_PROCESS")
            risk_score += 60
            mitre_ttps.append(_NETWORK_MITRE["DATA_EXFIL"])

        # Rule 5: DNS port (53) usage from non-DNS processes
        if remote_port == 53 and is_outbound and not is_loopback:
            if process_name.lower() not in {"svchost.exe", "dns.exe", "chrome.exe",
                                             "msedge.exe", "firefox.exe"}:
                threat_labels.append("POTENTIAL_DNS_TUNNEL")
                risk_score += 55
                mitre_ttps.append(_NETWORK_MITRE["DNS_TUNNEL"])

        return {
            "pid": conn["pid"],
            "process_name": process_name,
            "protocol": conn["protocol"],
            "local_addr": conn["local_addr"],
            "remote_addr": conn["remote_addr"],
            "state": conn["state"],
            "threat_labels": threat_labels,
            "risk_score": min(risk_score, 100),
            "mitre_ttps": list(dict.fromkeys(mitre_ttps)),
            "scan_timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
        }

    # ------------------------------------------------------------------
    #  Full Scan Orchestrator
    # ------------------------------------------------------------------

    def scan_connections(self) -> List[Dict[str, Any]]:
        """
        Top-level entry point: enumerate all TCP/UDP connections,
        map to processes, apply threat heuristics.
        """
        self.console.print(
            Panel(
                "[bold cyan]Network Connection Inspector[/bold cyan]\n"
                "[dim]Live TCP/UDP enumeration via iphlpapi.dll - zero dependencies[/dim]",
                border_style="bright_blue",
                box=box.ROUNDED,
                expand=False,
            )
        )

        pid_map = self._build_pid_map()

        with self.console.status(
            "[bold blue]Enumerating TCP connections...", spinner="dots"
        ):
            tcp_conns = self._get_tcp_connections()

        with self.console.status(
            "[bold blue]Enumerating UDP endpoints...", spinner="dots"
        ):
            udp_conns = self._get_udp_connections()

        all_conns = tcp_conns + udp_conns
        self.console.print(
            f"[bold green][PASS][/bold green] Found [cyan]{len(tcp_conns)}[/cyan] TCP + "
            f"[cyan]{len(udp_conns)}[/cyan] UDP connections "
            f"across [cyan]{len(set(c['pid'] for c in all_conns))}[/cyan] processes"
        )

        # Analyze each connection
        findings = []
        with self.console.status(
            "[bold blue]Analyzing connections for threat indicators...",
            spinner="bouncingBar",
        ):
            for conn in all_conns:
                process_name = pid_map.get(conn["pid"], f"PID_{conn['pid']}")
                analyzed = self._analyze_connection(conn, process_name)
                findings.append(analyzed)

        flagged = [f for f in findings if f["risk_score"] > 0]
        self.console.print(
            f"[bold green][PASS][/bold green] Analysis complete - "
            f"[{'bold red' if flagged else 'green'}]"
            f"{len(flagged)} suspicious connection(s) detected"
            f"[/{'bold red' if flagged else 'green'}]"
        )

        return findings

    # ------------------------------------------------------------------
    #  Display
    # ------------------------------------------------------------------

    def display_findings(
        self, findings: List[Dict[str, Any]], threats_only: bool = False
    ) -> None:
        """Render network findings as a rich console table."""
        if threats_only:
            displayable = [f for f in findings if f["risk_score"] > 0]
        else:
            displayable = findings

        if not displayable:
            self.console.print(
                Panel(
                    "[bold green][PASS] No suspicious network activity detected.[/bold green]",
                    border_style="green", box=box.ROUNDED, expand=False,
                )
            )
            return

        table = Table(
            title="[NETWORK] Network Connections" + (" - Threats Only" if threats_only else ""),
            title_style="bold red" if threats_only else "bold cyan",
            box=box.SIMPLE, show_lines=False,
            header_style="bold magenta",
            row_styles=["", "dim"], expand=True,
        )
        table.add_column("PID", style="cyan", justify="right", width=7)
        table.add_column("Process", style="white", width=22)
        table.add_column("Proto", style="dim", width=5)
        table.add_column("Local Address", style="bright_yellow", width=22)
        table.add_column("Remote Address", style="bright_yellow", width=22)
        table.add_column("State", style="dim", width=13)
        table.add_column("Threat", width=28)
        table.add_column("Risk", justify="center", style="bold", width=6)

        for f in sorted(displayable, key=lambda x: x["risk_score"], reverse=True):
            risk = f["risk_score"]
            risk_style = (
                "bold red" if risk >= 70
                else ("yellow" if risk >= 40
                      else ("white" if risk > 0 else "dim green"))
            )
            threat_text = ", ".join(f["threat_labels"]) if f["threat_labels"] else "CLEAN"
            threat_style = "bold red" if risk >= 50 else ("white" if risk > 0 else "dim green")

            table.add_row(
                str(f["pid"]),
                f["process_name"],
                f["protocol"],
                f["local_addr"],
                f["remote_addr"],
                f["state"],
                Text(threat_text, style=threat_style),
                Text(str(risk), style=risk_style),
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

        # Summary
        high = sum(1 for f in findings if f["risk_score"] >= 70)
        med = sum(1 for f in findings if 40 <= f["risk_score"] < 70)
        low = sum(1 for f in findings if 0 < f["risk_score"] < 40)
        clean = sum(1 for f in findings if f["risk_score"] == 0)

        summary = Text()
        summary.append("Network Scan Summary\n\n", style="bold underline")
        summary.append(f"  [CRITICAL]  Critical / High  : {high}\n", style="bold red")
        summary.append(f"  [HIGH]  Medium           : {med}\n", style="yellow")
        summary.append(f"  [INFO]  Low              : {low}\n", style="dim white")
        summary.append(f"  [OK]  Clean            : {clean}\n", style="dim green")
        summary.append(
            f"\n  Total connections: {len(findings)}  |  "
            f"Flagged: {high + med + low}",
            style="bold white",
        )

        self.console.print(
            Panel(
                summary,
                border_style="bright_blue" if high == 0 else "bright_red",
                box=box.HEAVY, expand=False,
            )
        )

    # ------------------------------------------------------------------
    #  Pipeline Output
    # ------------------------------------------------------------------

    def findings_to_correlated_events(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Convert network findings into CorrelatedEvent schema."""
        events = []
        for f in findings:
            if f["risk_score"] == 0:
                continue
            events.append({
                "timestamp": f["scan_timestamp_utc"],
                "source_module": "memory",  # network data feeds into memory correlation
                "event_type": "THREAT_DETECTED",
                "description": (
                    f"[Network] {', '.join(f['threat_labels'])} - "
                    f"{f['process_name']} (PID {f['pid']}) "
                    f"{f['protocol']} {f['local_addr']} -> {f['remote_addr']} "
                    f"[{f['state']}]"
                ),
                "risk_score": f["risk_score"],
                "mitre_attack_ttps": f.get("mitre_ttps", []),
            })
        return events

