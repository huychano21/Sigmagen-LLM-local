"""Unit tests for the 3-Stage Sigma Rule Verification Engine (Vòng A & B), Alert Adapter, and Wazuh XML Compiler."""
from __future__ import annotations

from pathlib import Path

from sigmagen.conversion.wazuh_xml import compile_sigma_to_wazuh_xml
from sigmagen.ingestion.alert_adapter import (
    load_alert_bundles,
    load_benign_background_events,
)
from sigmagen.validation.verifier import verify_and_score_sigma_rule

BASE_DIR = Path(__file__).resolve().parent.parent


def test_legacy_rule_fails_q2_and_q3() -> None:
    """The legacy rule using CommandLine on Sysmon EventID 11 (where command_line is null) must FAIL."""
    bundles = load_alert_bundles(
        BASE_DIR / "alert" / "ai_alerts_test.json",
        BASE_DIR / "alert" / "ai_alert_evidence_test.json",
    )
    benign = load_benign_background_events()
    legacy_yaml = (BASE_DIR / "output" / "from_alert" / "powershell_script_execution_in_temp_directory.yml").read_text(encoding="utf-8-sig")

    report = verify_and_score_sigma_rule(legacy_yaml, bundles[0], benign)
    assert report.q1_syntax_valid is True
    assert report.q2_data_match_valid is False
    assert report.tp == 0
    assert report.quality_gate == "FAIL - REJECT"
    assert report.confidence_score < 50.0


def test_verified_rule_passes_all_questions_and_compiles_to_wazuh_xml() -> None:
    """A telemetry-grounded Sigma rule for Sysmon EventID 11 must pass Q1, Q2, Q3 and compile to valid Wazuh XML."""
    bundles = load_alert_bundles(
        BASE_DIR / "alert" / "ai_alerts_test.json",
        BASE_DIR / "alert" / "ai_alert_evidence_test.json",
    )
    benign = load_benign_background_events()

    good_yaml = """\
title: PowerShell Script Policy Test File Created in Temp Directory
id: 2e319931-70f6-4b6c-a7df-2778faa3771a
status: experimental
description: Detects PowerShell creating script policy test files in user Temp folder.
references:
  - https://attack.mitre.org/techniques/T1105/
author: SigmaGen
date: '2026-10-26'
tags:
  - attack.t1105
logsource:
  product: windows
  category: file_event
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    TargetFilename|contains: '\\AppData\\Local\\Temp\\__PSScriptPolicyTest_'
    TargetFilename|endswith: '.ps1'
  condition: selection
falsepositives:
  - Legitimate administrative activity
level: high
"""
    report = verify_and_score_sigma_rule(good_yaml, bundles[0], benign)
    assert report.q1_syntax_valid is True
    assert report.q2_data_match_valid is True
    assert report.q3_behavior_valid is True
    assert report.tp == 1
    assert report.fp == 0
    assert report.generalization_rate == 1.0
    assert report.confidence_score >= 95.0
    assert report.quality_gate == "PASS - RECOMMEND_ADD"

    conv = compile_sigma_to_wazuh_xml(good_yaml, rule_id=100100, bundle=bundles[0])
    assert conv.xml_valid is True
    assert '<rule id="100100" level="12">' in conv.wazuh_xml
    assert "<if_group>sysmon_event_11</if_group>" in conv.wazuh_xml
    assert 'name="win.eventdata.targetFilename"' in conv.wazuh_xml
