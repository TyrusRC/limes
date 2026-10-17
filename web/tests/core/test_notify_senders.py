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
