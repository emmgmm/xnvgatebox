import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from worker.xncfbox import refresh


CSV = b"""*vpn_servers\n#HostName,IP,CountryShort,Score,OpenVPN_ConfigData_Base64\nvpn123,1.2.3.4,US,100,QUJD\nvpn123,1.2.3.4,US,50,QUJD\n"""


class RefreshTests(unittest.TestCase):
    def test_parse_csv_is_self_contained(self):
        rows = refresh.parse_csv(CSV)
        self.assertEqual(rows, [{"hostname": "vpn123.opengw.net", "country": "US", "score": 100}])

    def test_check_node_requires_two_matching_exits(self):
        responses = iter([
            {"type": "sstp", "success": True, "hostname": "vpn123.opengw.net", "port": 443, "exit": {"ip": "8.8.8.8"}},
            {"type": "sstp", "success": True, "hostname": "vpn123.opengw.net", "port": 443, "exit": {"ip": "8.8.8.8"}},
        ])

        class Response:
            def __enter__(self): return self
            def __exit__(self, *_): return None
            def read(self, _): return json.dumps(next(responses)).encode()

        with patch.object(refresh.urllib.request, "urlopen", return_value=Response()):
            node = refresh.check_node("https://xncfbox.example", "token", {"hostname": "vpn123.opengw.net", "country": "US", "score": 1}, 1)
        self.assertEqual(node["expected_exit_ip"], "8.8.8.8")
        self.assertEqual(node["actual_exit_ip"], "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
