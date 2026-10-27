import json
from unittest import mock

import requests
from django.test import TestCase

from limes import common_func
from limes.tasks import notifications
from scanEngine.models import Notification

HOOK = 'https://hooks.example.test/services/T0K3N'


class SenderFailureTest(TestCase):
    """A failing chat sender logs only the exception class: its URL carries a bot token or webhook secret."""
    def setUp(self):
        Notification.objects.create(
            send_to_telegram=True, telegram_bot_token='T0K3N', telegram_bot_chat_id='42',
            send_to_slack=True, slack_hook_url=HOOK, send_to_lark=True, lark_hook_url=HOOK,
            send_to_discord=True, discord_hook_url=HOOK)

    def assert_quiet_failure(self, send, target):
        boom = requests.exceptions.ConnectionError(f'Max retries for {HOOK} /botT0K3N/sendMessage')
        with mock.patch(target, side_effect=boom) as call, \
                self.assertLogs('limes.common_func', level='WARNING') as cm:
            send('hello')
        out = '\n'.join(cm.output)
        self.assertIn('ConnectionError', out)
        self.assertNotIn('T0K3N', out)
        self.assertEqual(call.call_args.kwargs['timeout'], 10)

    def test_telegram(self):
        self.assert_quiet_failure(common_func.send_telegram_message, 'requests.get')

    def test_slack(self):
        self.assert_quiet_failure(common_func.send_slack_message, 'requests.post')

    def test_lark(self):
        self.assert_quiet_failure(common_func.send_lark_message, 'requests.post')

    def test_discord(self):
        self.assert_quiet_failure(common_func.send_discord_message, 'requests.post')

    def test_one_failing_sender_does_not_stop_the_rest(self):
        with mock.patch('requests.post', side_effect=requests.exceptions.ConnectionError(HOOK)), \
                mock.patch.object(notifications, 'send_telegram_message') as telegram:
            notifications.send_notif('hello', title='')
        telegram.assert_called_once_with('hello')


class FakeCache:
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value


def reply(status=200, body=b'{"id": "777"}'):
    return mock.Mock(status_code=status, content=body)


class DiscordEmbedStateTest(TestCase):
    """The message id and embed kept between two alerts are JSON, never a pickle."""
    def setUp(self):
        Notification.objects.create(send_to_discord=True, discord_hook_url=HOOK)
        self.cache = FakeCache()
        patcher = mock.patch.object(common_func, 'DISCORD_WEBHOOKS_CACHE', self.cache)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_second_message_edits_the_first(self):
        with mock.patch('requests.post', return_value=reply()) as post, \
                mock.patch('requests.patch', return_value=reply()) as patch:
            common_func.send_discord_message('m', title='Scan 1', fields={'Status': 'RUNNING'})
            state = json.loads(self.cache.data['discord:Scan 1'])
            self.assertEqual(state['id'], '777')
            common_func.send_discord_message('m', title='Scan 1', fields={'Engine': 'quick'})
        post.assert_called_once()
        self.assertTrue(patch.call_args.args[0].endswith('/messages/777'))
        names = [f['name'] for f in patch.call_args.kwargs['json']['embeds'][0]['fields']]
        self.assertEqual(names, ['Status', 'Engine'])

    def test_cache_value_that_is_not_json_is_ignored(self):
        self.cache.data['discord:Scan 2'] = b'\x80\x04\x95not json'
        with mock.patch('requests.post', return_value=reply()) as post, \
                mock.patch('requests.patch') as patch:
            common_func.send_discord_message('m', title='Scan 2', fields={'Status': 'RUNNING'})
        post.assert_called_once()
        patch.assert_not_called()
