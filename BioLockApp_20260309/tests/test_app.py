"""
UI smoke test: drives the Streamlit app headlessly with streamlit.testing.

Run from the BioLockApp_20260309 directory:
    python -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

APP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_DIR))

import auth_manager  # noqa: E402
import file_storage  # noqa: E402

try:
    import streamlit as st
    from streamlit.testing.v1 import AppTest
except ImportError:  # pragma: no cover
    AppTest = None

PASSWORD = "Secret123"


def by_label(widgets, label):
    matches = [w for w in widgets if w.label == label]
    if not matches:
        raise AssertionError(f"No widget labelled {label!r}; have {[w.label for w in widgets]}")
    return matches[0]


@unittest.skipIf(AppTest is None, "streamlit is not installed")
class AppSmokeTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_dir = Path(self.tmp.name)
        for p in (
            mock.patch.dict(os.environ, {"BIOLOCK_DATA_DIR": str(self.data_dir)}),
            mock.patch.object(auth_manager, 'PBKDF2_ITERATIONS', 1000),
            mock.patch.object(file_storage, 'PASSPHRASE_ITERATIONS', 1000),
        ):
            p.start()
            self.addCleanup(p.stop)
        st.cache_resource.clear()
        self.addCleanup(st.cache_resource.clear)

        self.at = AppTest.from_file(str(APP_DIR / "app.py"), default_timeout=60)

    def run_app(self):
        self.at.run()
        if self.at.exception:
            self.fail(f"App raised: {[e.value for e in self.at.exception]}")
        return self.at

    def errors(self):
        return [e.value for e in self.at.error]

    def test_full_flow(self):
        at = self.run_app()

        # Register through the UI
        by_label(at.text_input, "Full Name").input("Alice Example")
        usernames = [w for w in at.text_input if w.label == "Username"]
        usernames[1].input("alice")
        emails = [w for w in at.text_input if w.label == "Email"]
        emails[0].input("alice@example.com")
        passwords = [w for w in at.text_input if w.label == "Password"]
        passwords[1].input(PASSWORD)
        by_label(at.text_input, "Confirm Password").input(PASSWORD)
        by_label(at.button, "Create Account").click()
        at = self.run_app()
        self.assertEqual(self.errors(), [])
        self.assertTrue(at.session_state.shown_recovery_key['key'])
        self.assertTrue((self.data_dir / "users" / "alice.json").exists())

        # Log in
        [w for w in at.text_input if w.label == "Username"][0].input("alice")
        [w for w in at.text_input if w.label == "Password"][0].input(PASSWORD)
        by_label(at.button, "Login").click()
        at = self.run_app()
        self.assertEqual(at.session_state.current_user['username'], "alice")
        self.assertIsNotNone(at.session_state.master_key)

        # Every page renders
        for page in ("dashboard", "storage", "restore", "my_files", "keys", "settings", "help"):
            at.session_state.current_page = page
            at = self.run_app()

        # Store a file in large file mode, encrypted with the password key
        source = self.data_dir / "sample.dat"
        payload = os.urandom(1_500_000)
        source.write_bytes(payload)

        at.session_state.current_page = "storage"
        at = self.run_app()
        by_label(at.radio, "Upload Mode").set_value("Large File Upload (Any Size)")
        at = self.run_app()
        by_label(at.text_input, "File Path").input(f'"{source}"')
        at = self.run_app()
        by_label(at.select_slider, "Slice Size").set_value(1)
        at = self.run_app()
        by_label(at.button, "Store File").click()
        at = self.run_app()
        self.assertEqual(self.errors(), [])
        self.assertTrue(any("stored successfully" in s.value for s in at.success))

        # Restore it
        at.session_state.current_page = "restore"
        at = self.run_app()
        by_label(at.button, "Select").click()
        at = self.run_app()
        out_dir = self.data_dir / "out"
        by_label(at.text_input, "Output Directory").input(str(out_dir))
        at = self.run_app()
        by_label(at.button, "Restore File").click()
        at = self.run_app()
        self.assertEqual(self.errors(), [])
        self.assertEqual((out_dir / "sample.dat").read_bytes(), payload)

        # Change password, log out, log back in, file still restores with the password key
        at.session_state.current_page = "settings"
        at = self.run_app()
        by_label(at.text_input, "Current Password").input(PASSWORD)
        by_label(at.text_input, "New Password").input("Changed789X")
        [w for w in at.text_input if w.label == "Confirm Password"][0].input("Changed789X")
        by_label(at.button, "Change Password").click()
        at = self.run_app()
        self.assertEqual(self.errors(), [])

        by_label(at.button, "Logout").click()
        at = self.run_app()
        self.assertIsNone(at.session_state.current_user)
        [w for w in at.text_input if w.label == "Username"][0].input("alice")
        [w for w in at.text_input if w.label == "Password"][0].input("Changed789X")
        by_label(at.button, "Login").click()
        at = self.run_app()

        at.session_state.current_page = "restore"
        at = self.run_app()
        by_label(at.button, "Select").click()
        at = self.run_app()
        by_label(at.text_input, "Output Directory").input(str(out_dir))
        by_label(at.checkbox, "Overwrite if the file already exists").check()
        at = self.run_app()
        by_label(at.button, "Restore File").click()
        at = self.run_app()
        self.assertEqual(self.errors(), [])
        self.assertEqual((out_dir / "sample.dat").read_bytes(), payload)

    def test_password_reset_demo_mode(self):
        users = auth_manager.UserManager(str(self.data_dir / "users"))
        recovery = users.create_user("bob", PASSWORD, "bob@example.com", "Bob")

        at = self.run_app()
        emails = [w for w in at.text_input if w.label == "Email"]
        emails[-1].input("bob@example.com")
        by_label(at.button, "Send Verification Code").click()
        with mock.patch.object(auth_manager.secrets, 'randbelow', return_value=123456):
            at = self.run_app()
        self.assertEqual(at.session_state.reset_username, "bob")

        by_label(at.text_input, "Verification Code").input("123456")
        by_label(at.text_input, "New Password").input("NewSecret456")
        [w for w in at.text_input if w.label == "Confirm Password"][-1].input("NewSecret456")
        by_label(at.text_input, "Recovery Key (optional)").input(recovery)
        by_label(at.button, "Reset Password").click()
        at = self.run_app()
        self.assertEqual(self.errors(), [])
        self.assertIsNotNone(users.authenticate_user("bob", "NewSecret456"))


if __name__ == "__main__":
    unittest.main()
