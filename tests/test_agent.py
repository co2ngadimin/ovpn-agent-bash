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

    def _write(self, body):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = os.path.join(d.name, "s.log")
        with open(p, "w") as f:
            f.write(body)
        return self.agent.get_openvpn_clients(p)

    def test_truncated_client_list_row_skipped_only(self):
        c = self._write("CLIENT_LIST\nCLIENT_LIST,andi,1.2.3.4:5,10.8.0.2,,1,2,x,1794884400\n")
        self.assertEqual([x["cn"] for x in c], ["andi"])

    def test_v3_tab_separated(self):
        c = self._write("CLIENT_LIST\tandi\t1.2.3.4:5\t10.8.0.2\t\t1\t2\tx\t1794884400\n")
        self.assertEqual(c, [{"cn": "andi", "realAddress": "1.2.3.4", "connectedSince": 1794884400}])

    def test_undef_skipped(self):
        c = self._write("CLIENT_LIST,UNDEF,1.2.3.4:5,,,1,2,x,1794884400\n"
                        "Common Name,Real Address,B,B,Connected Since\nUNDEF,1.2.3.4:5,1,2,garbage\n")
        self.assertEqual(c, [])

    def test_unbracketed_ipv6_kept(self):
        c = self._write("Common Name,Real Address,B,B,Connected Since\n"
                        "a,2001:db8::1:40000,1,2,garbage\nb,::ffff:1.2.3.4:5678,1,2,garbage\n"
                        "c,udp6:::ffff:1.2.3.4:5678,1,2,garbage\n")
        self.assertEqual([(x["cn"], x["realAddress"]) for x in c],
                         [("a", "2001:db8::1"), ("b", "::ffff:1.2.3.4"), ("c", "::ffff:1.2.3.4")])

    def test_agent_version(self):
        self.assertEqual(self.agent.AGENT_VERSION, "2.0.0-geo")

    def test_clients_missing_file(self):
        self.assertIsNone(self._get("nope.log"))

    def test_clients_unreadable_is_none(self):
        self.assertIsNone(self.agent.get_openvpn_clients(self.FIX))  # a directory -> exception

    def test_clients_empty_file_is_empty_list(self):
        self.assertEqual(self._write(""), [])

    def test_rows_after_end_ignored(self):
        c = self._write("CLIENT_LIST,andi,1.2.3.4:5,10.8.0.2,,1,2,x,1794884400\nEND\n"
                        "CLIENT_LIST,ghost,1.2.3.4:5,10.8.0.3,,1,2,x,1794884400\n")
        self.assertEqual([x["cn"] for x in c], ["andi"])

    def test_raw_log_line_capped(self):
        self.assertEqual(len(self.agent.package_raw_log_line("a" * 20000)["message"]), 10000)

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


class TailTest(unittest.TestCase):
    def setUp(self):
        self.agent = load_agent()
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.dir = d.name
        self.log = os.path.join(d.name, "user_activity.log")
        self.agent.STATE_FILE_PATH = os.path.join(d.name, "state.json")
        self.sent = []
        self.ok = True
        self.agent.send_batch = lambda b, e, h: (self.sent.extend(x["message"] for x in b), self.ok)[1]

    def _append(self, path, *lines):
        with open(path, "a") as f:
            f.write("".join(l + "\n" for l in lines))

    def _run(self, key="activity_log"):
        with contextlib.redirect_stdout(io.StringIO()):
            self.agent.process_log_file(key, self.log, self.agent.package_raw_log_line, "/x", {})
        got, self.sent = self.sent, []
        return got

    def test_first_run_activity_reads_from_start(self):
        self._append(self.log, "a", "b")
        self.assertEqual(self._run(), ["a", "b"])
        self.assertEqual(self._run(), [])

    def test_first_run_openvpn_log_skips_existing(self):
        self._append(self.log, "old")
        self.assertEqual(self._run("openvpn_log"), [])
        self._append(self.log, "new")
        self.assertEqual(self._run("openvpn_log"), ["new"])

    def test_rotation_reads_unread_tail_of_dot1_then_new_file(self):
        self._append(self.log, "a")
        self._run()
        self._append(self.log, "tail")
        os.rename(self.log, self.log + ".1")
        self._append(self.log, "new")
        self.assertEqual(self._run(), ["tail", "new"])
        self.assertEqual(self._run(), [])

    def test_rotation_without_matching_dot1_starts_new_file(self):
        self._append(self.log, "a")
        self._run()
        os.rename(self.log, self.log + ".old")
        self._append(self.log, "new")
        self.assertEqual(self._run(), ["new"])

    def test_rotation_keeps_state_when_tail_send_fails(self):
        self._append(self.log, "a")
        self._run()
        self._append(self.log, "tail")
        os.rename(self.log, self.log + ".1")
        self._append(self.log, "new")
        self.ok = False
        self._run()
        self.ok = True
        self.assertEqual(self._run(), ["tail", "new"])

    def test_truncation_resets_to_start(self):
        self._append(self.log, "aaaa", "bbbb")
        self._run()
        open(self.log, "w").close()
        self._append(self.log, "c")
        self.assertEqual(self._run(), ["c"])

    def test_state_written_atomically(self):
        self._append(self.log, "a")
        with mock.patch.object(self.agent.os, "replace", wraps=os.replace) as rep:
            self._run()
        rep.assert_called()
        self.assertEqual(sorted(os.listdir(self.dir)), ["state.json", "user_activity.log"])  # no temp file left


class ActivityParseTest(unittest.TestCase):
    def setUp(self):
        self.agent = load_agent()

    def test_disconnect_line(self):
        p = self.agent.parse_activity_log_line("2026-11-17 10:00:00,DISCONNECT,andi,1.2.3.4,100,200")
        self.assertEqual((p["action"], p["username"], p["publicIp"], p["vpnIp"], p["bytesReceived"], p["bytesSent"]),
                         ("DISCONNECT", "andi", "1.2.3.4", None, 100, 200))

    def test_malformed_lines(self):
        for line in ("garbage", "", "not-a-date,CONNECT,andi", "2026-11-17 10:00:00,DISCONNECT,andi,1.2.3.4,x,y"):
            self.assertIsNone(self.agent.parse_activity_log_line(line), line)


class ServerCnFallbackTest(unittest.TestCase):
    def test_get_server_cn_fallback_empty(self):
        agent = load_agent()
        agent.EASY_RSA_SERVER_NAME_PATH = "/nonexistent/SERVER_NAME_GENERATED"
        self.assertEqual(agent.get_server_cn(), "")


if __name__ == "__main__":
    unittest.main()
