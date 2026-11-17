import contextlib
import io
import os
import tempfile
import time
import unittest
from unittest import mock

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


class ClientsTest(unittest.TestCase):
    FIX = os.path.join(os.path.dirname(__file__), "fixtures")

    def setUp(self):
        self.agent = load_agent()
        self.old_tz = os.environ.get("TZ")
        self.addCleanup(self._restore_tz)
        os.environ["TZ"] = "Asia/Jakarta"
        time.tzset()

    def _restore_tz(self):
        if self.old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self.old_tz
        time.tzset()

    def _get(self, name):
        return self.agent.get_openvpn_clients(os.path.join(self.FIX, name))

    def test_clients_v1_26(self):
        c = self._get("status-v1-26.log")
        self.assertEqual(len(c), 3)
        self.assertEqual(c[0], {"cn": "andi", "realAddress": "103.10.20.30", "connectedSince": 1794884400})
        self.assertEqual(c[1]["realAddress"], "36.80.1.2")
        self.assertEqual(c[2]["realAddress"], "2001:db8::1")

    def test_clients_v1_24(self):
        self.assertEqual(self._get("status-v1-24.log")[0]["connectedSince"], 1794884400)

    def test_clients_v2_uses_since_t(self):
        c = self._get("status-v2.log")
        self.assertEqual(c[0]["connectedSince"], 1794884400)
        self.assertEqual(c[0]["realAddress"], "103.10.20.30")

    def test_clients_missing_file(self):
        self.assertEqual(self._get("nope.log"), [])

    def test_clients_bad_time(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.log")
            with open(p, "w") as f:
                f.write("Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n"
                        "x,1.2.3.4:5,1,2,garbage\nROUTING TABLE\n")
            c = self.agent.get_openvpn_clients(p)
        self.assertEqual(len(c), 1)
        self.assertIsNone(c[0]["connectedSince"])


class SendBatchTest(unittest.TestCase):
    def setUp(self):
        self.agent = load_agent()

    def _send(self, status):
        resp = mock.Mock(status_code=status)
        if status >= 400:
            resp.raise_for_status.side_effect = self.agent.requests.HTTPError(str(status))
        with mock.patch.object(self.agent.requests, "post", return_value=resp), \
                contextlib.redirect_stdout(io.StringIO()):
            return self.agent.send_batch([{"a": 1}], "/api/openvpn-logs", {})

    def test_send_batch_ok_on_200(self):
        self.assertTrue(self._send(200))

    def test_send_batch_skips_on_4xx(self):
        self.assertTrue(self._send(422))

    def test_send_batch_retries_on_5xx(self):
        self.assertFalse(self._send(503))

    def test_send_batch_retries_on_429(self):
        self.assertFalse(self._send(429))

    def test_send_batch_retries_on_401(self):
        self.assertFalse(self._send(401))


if __name__ == "__main__":
    unittest.main()
