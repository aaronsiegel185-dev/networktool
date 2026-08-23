"""The macOS Location Services bridge, as far as it can be exercised off macOS."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import maclocation


class TestLocationBridge(unittest.TestCase):
    def test_status_names_cover_the_documented_codes(self):
        # kCLAuthorizationStatus* values from <CoreLocation/CLLocation.h>.
        for code in range(5):
            self.assertIn(code, maclocation.STATUS_NAMES)
        self.assertEqual(maclocation.GRANTED, (3, 4))
        for code in maclocation.GRANTED:
            self.assertIn("authoris", maclocation.STATUS_NAMES[code])

    @unittest.skipIf(sys.platform == "darwin", "this is the non-macOS path")
    def test_fails_clearly_off_macos_rather_than_importing_nothing(self):
        for call in (maclocation.status, maclocation.services_enabled,
                     maclocation.request):
            with self.assertRaises(maclocation.LocationError):
                call()

    def test_module_imports_without_a_mac(self):
        # Loading the frameworks is deferred, so importing must never explode -
        # the CLI imports this module on every platform to report why not.
        self.assertTrue(hasattr(maclocation, "request"))


if __name__ == "__main__":
    unittest.main()
