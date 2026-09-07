"""One cadence for the two shipped data files.

BotShieldBotDirectoryRefreshInterval and
BotShieldBrowserTemplatesRefreshInterval were the same directive twice
-- same 0..86400 range, same 0-means-300, same watchdog registration --
over two files of the same kind, and neither had ever been set. They
became BotShieldDataRefreshInterval on 2026-09-07.

BotShieldAllowRangesRefreshInterval was NOT folded in, and the reason
is the whole care in this change: 0 there leaves the watchdog
unregistered rather than selecting a default, so verified-bot CIDR
refresh is opt-in and currently off. Consolidating it under a 300s
default would have switched it on in production.
"""

from __future__ import annotations

import pytest

from botshield_test import client


def _srv(line: str) -> str:
    return 'BotShieldEnabled On\n    ' + line


def test_the_shared_directive_is_accepted(config_override):
    with config_override(r'BotShieldEnabled\s+On',
                         _srv('BotShieldDataRefreshInterval 600'),
                         render=False, count=1):
        r = client.get('/', ua='probe/1.0')
    assert r.status_code < 500, f'server unhealthy: {r.status_code}'


def test_zero_is_accepted_as_the_default(config_override):
    """0 selects 300 rather than disabling. The docs said 0=disabled
    for both predecessors; the code has always read 0 as the default,
    and that mismatch came along with the rows being rewritten."""
    with config_override(r'BotShieldEnabled\s+On',
                         _srv('BotShieldDataRefreshInterval 0'),
                         render=False, count=1):
        r = client.get('/', ua='probe/1.0')
    assert r.status_code < 500, f'server unhealthy: {r.status_code}'


@pytest.mark.parametrize('bad', ['-1', '86401', 'often', '5m', ''])
def test_bad_values_are_refused(config_override, bad):
    with pytest.raises(Exception):
        with config_override(r'BotShieldEnabled\s+On',
                             _srv('BotShieldDataRefreshInterval ' + bad),
                             render=False, count=1):
            pass


@pytest.mark.parametrize('gone', [
    'BotShieldBotDirectoryRefreshInterval 300',
    'BotShieldBrowserTemplatesRefreshInterval 300',
])
def test_the_replaced_spellings_are_refused(config_override, gone):
    """They fail parse rather than being ignored -- a silently dropped
    cadence would leave an operator believing they had changed one."""
    with pytest.raises(Exception):
        with config_override(r'BotShieldEnabled\s+On', _srv(gone),
                             render=False, count=1):
            pass


def test_allow_ranges_keeps_its_own_directive(config_override):
    """The one that was deliberately left alone."""
    with config_override(r'BotShieldEnabled\s+On',
                         _srv('BotShieldAllowRangesRefreshInterval 900'),
                         render=False, count=1):
        r = client.get('/', ua='probe/1.0')
    assert r.status_code < 500, f'server unhealthy: {r.status_code}'
