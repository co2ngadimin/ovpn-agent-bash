import os
import time
import unittest

from tests.agent_loader import load_agent

LINE = "2026-11-17 10:00:00,CONNECT,andi,1.2.3.4,10.8.0.2"


class ActivityTimestampTest(unittest.TestCase):
    def setUp(self):
        self.agent = load_agent()
        self.old_tz = os.environ.get("TZ")
        self.addCleanup(self._restore_tz)

    def _restore_tz(self):
        if self.old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self.old_tz
        time.tzset()

    def _ts(self, tz):
        os.environ["TZ"] = tz
        time.tzset()
        return self.agent.parse_activity_log_line(LINE)["timestamp"]

    def test_activity_timestamp_is_converted_from_local_to_utc(self):
        ts = self._ts("Asia/Jakarta")
        self.assertTrue(ts.startswith("2026-11-17T03:00:00"), ts)
        self.assertTrue(ts.endswith("+00:00"), ts)

    def test_activity_timestamp_utc_host_unchanged(self):
        self.assertEqual(self._ts("UTC"), "2026-11-17T10:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
