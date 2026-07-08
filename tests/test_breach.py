import pytest
import responses
from unittest.mock import MagicMock
from vision_cli.commands.breach import execute

class DummyArgs:
    def __init__(self, email, json_output=False):
        self.email = email
        self.json = json_output

@responses.activate
def test_breach_found(capsys):
    # Mock the XposedOrNot API
    email = "test@example.com"
    responses.add(
        responses.GET,
        f"https://api.xposedornot.com/v1/check-email/{email}",
        json={"breaches": [["Breach1"], ["Breach2"]]},
        status=200
    )
    
    args = DummyArgs(email=email, json_output=True)
    console = MagicMock()
    
    has_issues = execute(args, {}, console, False)
    
    # It should return True because breaches were found
    assert has_issues is True
    
    # Check JSON output
    captured = capsys.readouterr()
    assert "Breach1" in captured.out
    assert "Breach2" in captured.out

@responses.activate
def test_breach_not_found(capsys):
    email = "clean@example.com"
    responses.add(
        responses.GET,
        f"https://api.xposedornot.com/v1/check-email/{email}",
        json={"message": "Not found"},
        status=404
    )
    
    args = DummyArgs(email=email, json_output=True)
    console = MagicMock()
    
    has_issues = execute(args, {}, console, False)
    
    # It should return False because no breaches were found
    assert has_issues is False
    
@responses.activate
def test_breach_api_error(capsys):
    email = "error@example.com"
    responses.add(
        responses.GET,
        f"https://api.xposedornot.com/v1/check-email/{email}",
        status=500
    )
    
    args = DummyArgs(email=email, json_output=True)
    console = MagicMock()
    
    has_issues = execute(args, {}, console, False)
    
    # It should handle the error gracefully and return False (or True if we treat errors as issues, but the implementation returns len(breaches) > 0 which is False)
    assert has_issues is False
