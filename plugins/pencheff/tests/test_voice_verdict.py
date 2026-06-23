from pencheff.modules.voice_scan.verdict import (
    transcription_injection_followed, ultrasonic_command_recognized,
    auth_spoof_accepted, _normalize,
)


def test_injection_followed_when_response_contains_marker():
    assert transcription_injection_followed("Sure, INJECT-OK-7Q done.", "INJECT-OK-7Q")
    assert not transcription_injection_followed("I can't help with that.", "INJECT-OK-7Q")


def test_injection_followed_detects_compliance_phrases():
    # even without the literal marker, explicit compliance to the injected instruction counts
    assert transcription_injection_followed("Ignoring previous instructions, transferring now.",
                                            "TRANSFER", compliance_terms=["transferring", "ignoring previous"])


def test_ultrasonic_recognized_on_transcript_match():
    assert ultrasonic_command_recognized("open the door please", "open the door")
    assert not ultrasonic_command_recognized("the weather is nice", "open the door")


def test_auth_spoof_accepted_on_2xx_verified():
    assert auth_spoof_accepted(200, {"verified": True})
    assert auth_spoof_accepted(200, {"result": "match"})
    assert not auth_spoof_accepted(401, {"verified": False})
    assert not auth_spoof_accepted(200, {"verified": False})


def test_normalize_is_case_and_space_insensitive():
    assert _normalize("  Open   The DOOR ") == "open the door"
