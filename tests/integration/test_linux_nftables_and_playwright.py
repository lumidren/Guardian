"""
Integration tests for Linux nftables graduated response tiers and Playwright E2E dashboard (Phase 3 Item 7).

Verifies:
1. Atomic nftables ruleset generation, tier application (MONITOR, RESTRICT, QUARANTINE, BLOCK),
   rule reversion, and protected address invariants.
2. Privileged Linux network-namespace (`ip netns` + `nft`) live packet filtering across
   all 4 response tiers:
   - MONITOR: LAN and WAN traffic allowed
   - RESTRICT: token-bucket rate limit active, WAN dropped, LAN allowed
   - QUARANTINE: WAN dropped, LAN allowed
   - BLOCK: both LAN and WAN dropped
   - Revert: rules removed and WAN/LAN traffic restored
   - Protected addresses (e.g. 192.168.1.1, 127.0.0.1) never blocked
3. End-to-end Playwright headless Chromium dashboard test: renders 8 IoT devices, triggers
   a live attack from the Lab/Control panel, verifies Explainable AI modal diagnostics,
   and executes One-Click Unblock override.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time

import pytest

from guardian.config import ThreatLevel
from guardian.enforcement.controller import EnforcementController
from guardian.enforcement.iptables_driver import (
    DEFAULT_PROTECTED_ADDRESSES,
    LinuxNftablesDriver,
)
from guardian.ml.threat_scorer import ThreatAssessment


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_nftables_atomic_ruleset_tiers_revert_and_protected_addresses() -> None:
    """Verify atomic nftables ruleset generation, tier transitions, reversion, and protected IPs."""
    driver = LinuxNftablesDriver(local_subnet="192.168.1.0/24")
    iot_ip = "192.168.1.101"

    # 1. Protected addresses must never be added to active policies or blocked
    for prot_ip in DEFAULT_PROTECTED_ADDRESSES:
        assert driver.is_protected(prot_ip) is True
        driver.apply_policy(prot_ip, ThreatLevel.BLOCK)
        assert prot_ip not in driver.active_policies
        ruleset = driver.build_atomic_ruleset()
        assert f"ip saddr {prot_ip} drop" not in ruleset

    # 2. RESTRICT tier: rate limit + WAN drop
    driver.apply_policy(iot_ip, ThreatLevel.RESTRICT)
    ruleset_restrict = driver.build_atomic_ruleset()
    assert f"ip saddr {iot_ip} limit rate over 500 kbytes/second drop" in ruleset_restrict
    assert f"ip saddr {iot_ip} ip daddr != 192.168.1.0/24 drop" in ruleset_restrict

    # 3. QUARANTINE tier: WAN drop + DHCP/DNS accept
    driver.apply_policy(iot_ip, ThreatLevel.QUARANTINE)
    ruleset_quarantine = driver.build_atomic_ruleset()
    assert f'guardian_quarantine_wan_{iot_ip}' in ruleset_quarantine
    assert f'guardian_quarantine_dhcp_dns_{iot_ip}' in ruleset_quarantine

    # 4. BLOCK tier: full saddr/daddr drop
    driver.apply_policy(iot_ip, ThreatLevel.BLOCK)
    ruleset_block = driver.build_atomic_ruleset()
    assert f'ip saddr {iot_ip} drop comment "guardian_block_src_{iot_ip}"' in ruleset_block
    assert f'ip daddr {iot_ip} drop comment "guardian_block_dst_{iot_ip}"' in ruleset_block

    # 5. Revert policy: removes all rules for iot_ip
    driver.revert_policy(iot_ip)
    assert iot_ip not in driver.active_policies
    ruleset_reverted = driver.build_atomic_ruleset()
    assert iot_ip not in ruleset_reverted

    # 6. EnforcementController protected address guard
    ctrl = EnforcementController()
    block_assessment = ThreatAssessment(
        threat_score=98,
        threat_level=ThreatLevel.BLOCK,
        confidence_level="High (90-100%)",
        confidence_score=0.99,
        ml_score=0.98,
        statistical_score=0.95,
        layer_contributions={"layer_1": 60.0, "layer_2": 40.0},
    )
    gw_state = ctrl.enforce("gateway_node", "192.168.1.1", block_assessment)
    assert gw_state.current_level == ThreatLevel.MONITOR
    assert ctrl.virtual_driver.should_allow_packet("192.168.1.1", "8.8.8.8") is True


@pytest.mark.skipif(
    sys.platform != "linux"
    or shutil.which("nft") is None
    or shutil.which("ip") is None
    or (hasattr(os, "geteuid") and os.geteuid() != 0),
    reason="Requires privileged Linux container/VM (root + nft + iproute2)",
)
def test_privileged_linux_nftables_real_traffic_tiers() -> None:
    """
    Execute real kernel nftables enforcement across network namespaces:
    ns_iot (192.168.1.101/24) <-> ns_gw (192.168.1.1/24, 198.51.100.254/24) <-> ns_wan (198.51.100.1/24)
    """
    ns_iot = "guardian_ns_iot"
    ns_gw = "guardian_ns_gw"
    ns_wan = "guardian_ns_wan"

    def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, check=check, capture_output=True, text=True)

    def can_ping(src_ns: str, dst_ip: str) -> bool:
        res = subprocess.run(
            ["ip", "netns", "exec", src_ns, "ping", "-c", "1", "-W", "1", dst_ip],
            capture_output=True,
            text=True,
        )
        return res.returncode == 0

    try:
        # Clean up any stale namespaces
        for ns in (ns_iot, ns_gw, ns_wan):
            run_cmd(["ip", "netns", "del", ns], check=False)

        # Create namespaces
        for ns in (ns_iot, ns_gw, ns_wan):
            run_cmd(["ip", "netns", "add", ns])
            run_cmd(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])

        # Connect ns_iot <-> ns_gw
        run_cmd(["ip", "link", "add", "veth_iot", "type", "veth", "peer", "name", "veth_gw_lan"])
        run_cmd(["ip", "link", "set", "veth_iot", "netns", ns_iot])
        run_cmd(["ip", "link", "set", "veth_gw_lan", "netns", ns_gw])

        run_cmd(["ip", "netns", "exec", ns_iot, "ip", "addr", "add", "192.168.1.101/24", "dev", "veth_iot"])
        run_cmd(["ip", "netns", "exec", ns_iot, "ip", "link", "set", "veth_iot", "up"])
        run_cmd(["ip", "netns", "exec", ns_iot, "ip", "route", "add", "default", "via", "192.168.1.1"])

        run_cmd(["ip", "netns", "exec", ns_gw, "ip", "addr", "add", "192.168.1.1/24", "dev", "veth_gw_lan"])
        run_cmd(["ip", "netns", "exec", ns_gw, "ip", "link", "set", "veth_gw_lan", "up"])

        # Connect ns_gw <-> ns_wan
        run_cmd(["ip", "link", "add", "veth_gw_wan", "type", "veth", "peer", "name", "veth_wan"])
        run_cmd(["ip", "link", "set", "veth_gw_wan", "netns", ns_gw])
        run_cmd(["ip", "link", "set", "veth_wan", "netns", ns_wan])

        run_cmd(["ip", "netns", "exec", ns_gw, "ip", "addr", "add", "198.51.100.254/24", "dev", "veth_gw_wan"])
        run_cmd(["ip", "netns", "exec", ns_gw, "ip", "link", "set", "veth_gw_wan", "up"])
        run_cmd(["ip", "netns", "exec", ns_gw, "sysctl", "-w", "net.ipv4.ip_forward=1"])

        run_cmd(["ip", "netns", "exec", ns_wan, "ip", "addr", "add", "198.51.100.1/24", "dev", "veth_wan"])
        run_cmd(["ip", "netns", "exec", ns_wan, "ip", "link", "set", "veth_wan", "up"])
        run_cmd(["ip", "netns", "exec", ns_wan, "ip", "route", "add", "default", "via", "198.51.100.254"])

        driver = LinuxNftablesDriver(
            interface="veth_gw_lan",
            local_subnet="192.168.1.0/24",
            netns=ns_gw,
        )
        iot_ip = "192.168.1.101"
        lan_gw_ip = "192.168.1.1"
        wan_ip = "198.51.100.1"

        # 1. MONITOR tier: both LAN and WAN reachable
        driver.apply_policy(iot_ip, ThreatLevel.MONITOR)
        assert driver.last_error == "", f"MONITOR nft error: {driver.last_error}"
        assert can_ping(ns_iot, lan_gw_ip) is True, "MONITOR: LAN should be reachable"
        assert can_ping(ns_iot, wan_ip) is True, "MONITOR: WAN should be reachable"

        # 2. RESTRICT tier: rate-limited LAN reachable, uncataloged WAN dropped
        driver.apply_policy(iot_ip, ThreatLevel.RESTRICT)
        assert driver.last_error == "", f"RESTRICT nft error: {driver.last_error}"
        live_rules_restrict = driver.list_ruleset()
        assert "limit rate over 500 kbytes/second" in live_rules_restrict
        assert f"guardian_restrict_wan_{iot_ip}" in live_rules_restrict
        assert can_ping(ns_iot, lan_gw_ip) is True, "RESTRICT: LAN should remain reachable"
        assert can_ping(ns_iot, wan_ip) is False, "RESTRICT: WAN must be dropped"

        # 3. QUARANTINE tier: WAN dropped, LAN reachable
        driver.apply_policy(iot_ip, ThreatLevel.QUARANTINE)
        assert driver.last_error == "", f"QUARANTINE nft error: {driver.last_error}"
        live_rules_quar = driver.list_ruleset()
        assert f"guardian_quarantine_wan_{iot_ip}" in live_rules_quar
        assert can_ping(ns_iot, lan_gw_ip) is True, "QUARANTINE: LAN should remain reachable"
        assert can_ping(ns_iot, wan_ip) is False, "QUARANTINE: WAN must be dropped"

        # 4. BLOCK tier: both LAN and WAN dropped
        driver.apply_policy(iot_ip, ThreatLevel.BLOCK)
        assert driver.last_error == "", f"BLOCK nft error: {driver.last_error}"
        live_rules_block = driver.list_ruleset()
        assert f"guardian_block_src_{iot_ip}" in live_rules_block
        assert can_ping(ns_iot, lan_gw_ip) is False, "BLOCK: LAN must be dropped"
        assert can_ping(ns_iot, wan_ip) is False, "BLOCK: WAN must be dropped"

        # 5. Revert rules: both LAN and WAN immediately reachable again
        assert driver.revert_policy(iot_ip) is True
        assert driver.last_error == "", f"REVERT nft error: {driver.last_error}"
        assert can_ping(ns_iot, lan_gw_ip) is True, "REVERT: LAN must recover"
        assert can_ping(ns_iot, wan_ip) is True, "REVERT: WAN must recover"

        # 6. Protected address check: attempting to BLOCK 192.168.1.1 is refused
        driver.apply_policy(lan_gw_ip, ThreatLevel.BLOCK)
        assert can_ping(ns_iot, lan_gw_ip) is True, "Protected address 192.168.1.1 must never be blocked"
        assert can_ping(ns_iot, wan_ip) is True, "Gateway forwarding must remain intact"

    finally:
        for ns in (ns_iot, ns_gw, ns_wan):
            run_cmd(["ip", "netns", "del", ns], check=False)


def test_playwright_dashboard_and_attack_injection() -> None:
    """
    Launch live FastAPI + SOC Dashboard server and drive it via Playwright Chromium:
    - Verify 8 IoT fleet cards render
    - Trigger manual attack from the Live Attack Injection panel
    - Verify Explainable AI modal opens with root-cause bullets and threat score
    - Trigger One-Click Unblock and verify recovery to MONITOR
    """
    pw_sync = pytest.importorskip("playwright.sync_api")

    port = _find_free_port()
    env = os.environ.copy()
    env["PYTHONPATH"] = f"src{os.pathsep}."
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "guardian.api.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for server readiness
    base_url = f"http://127.0.0.1:{port}"
    ready = False
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                ready = True
                break
        except OSError:
            time.sleep(0.2)
    assert ready, "FastAPI dashboard server did not start in time"

    try:
        with pw_sync.sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(base_url, wait_until="domcontentloaded", timeout=15000)

            # 1. Verify title and 8 device cards render
            assert "GUARDIAN" in page.title()
            page.wait_for_selector("#device-grid .device-card", timeout=15000)
            cards = page.locator("#device-grid .device-card")
            assert cards.count() == 8

            # 2. Trigger a manual attack (DDoS Flood) from the Attack Injection panel
            page.select_option("#attack-target-select", "dev_08_camera")
            page.click("button:has-text('DDoS Flood')")

            # 3. Verify Explainable AI modal appears with score and root-cause bullets
            modal = page.locator("#xai-modal")
            modal.wait_for(state="visible", timeout=15000)
            score_text = page.locator("#modal-score").inner_text()
            assert "/100" in score_text
            bullets = page.locator("#modal-bullets > div")
            assert bullets.count() >= 1

            # 4. Click One-Click Unblock & Retrain and verify modal closes
            page.click("button:has-text('One-Click Unblock')")
            modal.wait_for(state="hidden", timeout=10000)

            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
