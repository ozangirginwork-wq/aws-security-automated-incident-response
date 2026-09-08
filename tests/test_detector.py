import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "lambda"))

from detector import detect_public_ssh


def load_attack_event():
    event_file = PROJECT_ROOT / "sample-events" / "unsafe-security-group.json"

    with open(event_file, "r", encoding="utf-8") as file:
        return json.load(file)


def test_detects_public_ssh():
    event = load_attack_event()

    assert detect_public_ssh(event) is True


def test_allows_restricted_ssh():
    event = load_attack_event()

    event["detail"]["requestParameters"]["ipPermissions"]["items"][0][
        "ipRanges"
    ]["items"][0]["cidrIp"] = "10.0.0.0/24"

    assert detect_public_ssh(event) is False


def test_allows_public_https():
    event = load_attack_event()

    permission = event["detail"]["requestParameters"]["ipPermissions"]["items"][0]
    permission["fromPort"] = 443
    permission["toPort"] = 443

    assert detect_public_ssh(event) is False


def test_ignores_unrelated_api_event():
    event = load_attack_event()

    event["detail"]["eventName"] = "DescribeInstances"

    assert detect_public_ssh(event) is False