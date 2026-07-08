import pytest
import responses
from unittest.mock import MagicMock, patch
from vision_cli.commands.phish import execute

class DummyArgs:
    def __init__(self, url, json_output=False):
        self.url = url
        self.json = json_output

@responses.activate
@patch('vision_cli.commands.phish.socket.create_connection')
@patch('vision_cli.commands.phish.ssl.create_default_context')
def test_phish_malicious(mock_ssl, mock_socket, capsys):
    # Mock network for VT and PhishStats
    url = "http://192.168.1.1/login.php"
    
    responses.add(
        responses.GET,
        "https://phishstats.info:2096/api/phishing?_where=(url,eq,http://192.168.1.1/login.php)",
        json=[{"url": url}],
        status=200
    )
    
    args = DummyArgs(url=url, json_output=True)
    console = MagicMock()
    
    # Force SSL validation to fail
    mock_socket.side_effect = Exception("Connection Refused")
    
    has_issues = execute(args, {}, console, False)
    
    # Should return True since risk score will be >= 60 (PhishStats=100, IP=40, SSL=25)
    assert has_issues is True

@responses.activate
@patch('vision_cli.commands.phish.socket.create_connection')
@patch('vision_cli.commands.phish.ssl.create_default_context')
def test_phish_safe(mock_ssl, mock_socket, capsys):
    url = "https://google.com"
    
    responses.add(
        responses.GET,
        "https://phishstats.info:2096/api/phishing?_where=(url,eq,https://google.com)",
        json=[],
        status=200
    )
    
    args = DummyArgs(url=url, json_output=True)
    console = MagicMock()
    
    # Mock SSL to simulate valid cert
    mock_ctx = MagicMock()
    mock_ssl.return_value = mock_ctx
    mock_ss = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ss
    # cert age 100 days
    mock_ss.getpeercert.return_value = {'notBefore': 'Jan 01 00:00:00 2024 GMT'}
    
    has_issues = execute(args, {}, console, False)
    
    # Should return False (0 risk score)
    assert has_issues is False
