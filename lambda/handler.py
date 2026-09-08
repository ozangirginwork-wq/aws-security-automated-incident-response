from detector import detect_public_ssh
from investigator import investigate_event
from remediation import remediate_public_ssh
from verifier import verify_remediation


def lambda_handler(event, context=None):
    """
    Main AWS incident-response pipeline:
    Detect -> Investigate -> Respond -> Verify
    """

    print("=== AWS INCIDENT RESPONSE STARTED ===")

    # Stage 1: Detect
    if not detect_public_ssh(event):
        print("[DETECT] No dangerous public SSH exposure detected.")
        return {
            "status": "NO_ACTION",
            "message": "Event did not match detection criteria."
        }

    print("[DETECT] HIGH severity public SSH exposure detected.")

    # Stage 2: Investigate
    incident = investigate_event(event)

    print("[INVESTIGATE]")
    for key, value in incident.items():
        print(f"  {key}: {value}")

    # Stage 3: Respond
    response = remediate_public_ssh(incident, dry_run=False)

    print("[RESPOND]")
    for key, value in response.items():
        print(f"  {key}: {value}")

    # Stage 4: Verify
    verification = verify_remediation(response)

    print("[VERIFY]")
    for key, value in verification.items():
        print(f"  {key}: {value}")

    return {
        "status": "INCIDENT_HANDLED",
        "incident": incident,
        "response": response,
        "verification": verification
    }