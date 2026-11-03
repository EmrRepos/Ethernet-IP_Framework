import tkinter as tk
import unittest
from unittest.mock import patch

from ui import AssessmentApp


class UITests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = AssessmentApp(self.root)

    def tearDown(self):
        self.root.destroy()

    def test_sample_review_and_report_without_network(self):
        with patch('modules.discovery.socket.create_connection') as connect:
            self.app.load_sample()
            self.app.catalog.selection_set('EIP-01')
            self.app._select_surface()
            self.app.review_status.set('Needs review')
            self.app.notes.insert('1.0', 'Synthetic review evidence')
            self.app.save_review()
            report = self.app.build_report()
            connect.assert_not_called()
        self.assertEqual(report['scope']['mode'], 'sample')
        self.assertFalse(report['scope']['authorization_attested'])
        self.assertEqual(report['attack_surface_reviews'][0]['status'], 'Needs review')

    def test_changed_scope_cannot_relabel_evidence(self):
        self.app.load_sample()
        self.app.target.set('192.0.2.11')
        with self.assertRaisesRegex(ValueError, 'Scope changed'):
            self.app.build_report()

    def test_unauthorized_probe_never_opens_socket(self):
        self.app.operator.set('Tester / lab ticket')
        with patch('ui.messagebox.showerror') as error, patch('modules.discovery.socket.create_connection') as connect:
            self.app.start_probe()
            error.assert_called_once()
            connect.assert_not_called()

    def test_queued_error_is_inconclusive(self):
        self.app.events.put(('error', 'timed out'))
        self.app._poll()
        self.assertFalse(self.app.busy)
        self.assertIn('inconclusive', self.app.outcome)
        self.assertEqual(self.app.assessment.observations(self.app.identities), [])

    def test_unsaved_notes_are_not_lost_on_selection(self):
        self.app.catalog.selection_set('EIP-01')
        self.app._select_surface()
        self.app.notes.insert('1.0', 'Unsaved evidence')
        self.app.catalog.selection_set('EIP-02')
        with patch('ui.messagebox.askyesno', return_value=False):
            self.app._select_surface()
            self.app._select_surface()
        self.assertEqual(self.app.selected, 'EIP-01')
        self.assertEqual(self.app.notes.get('1.0', 'end').strip(), 'Unsaved evidence')

    def test_live_probe_scope_busy_state_and_success(self):
        self.app.operator.set('Tester / lab ticket')
        self.app.authorized.set(True)
        with patch('ui.messagebox.askyesno', return_value=True), patch('ui.threading.Thread') as thread:
            self.app.start_probe()
            self.assertTrue(self.app.busy)
            self.assertEqual(str(self.app.target_entry.cget('state')), 'disabled')
            self.app.start_probe()
            thread.assert_called_once()
        self.app.events.put(('success', []))
        self.app._poll()
        self.assertFalse(self.app.busy)
        self.assertIn('inconclusive', self.app.outcome)
        self.app.authorized.set(False)
        report = self.app.build_report()
        self.assertEqual(report['scope']['mode'], 'live')
        self.assertTrue(report['scope']['authorization_attested'])
        self.assertIsNotNone(report['scope']['observed_at_utc'])

    def test_desktop_window_layout(self):
        self.root.deiconify()
        for width, height in ((1180, 820), (820, 650)):
            self.root.geometry(f'{width}x{height}')
            self.app.notebook.select(1)
            self.root.update()
            for widget in (self.app.probe_button, self.app.export_button, self.app.catalog,
                           self.app.notes, self.app.save_button, self.app.suite_button, self.app.stop_button):
                with self.subTest(size=(width, height), widget=widget):
                    self.assertLessEqual(widget.winfo_rootx() + widget.winfo_width(),
                                         self.root.winfo_rootx() + self.root.winfo_width())
                    self.assertLessEqual(widget.winfo_rooty() + widget.winfo_height(),
                                         self.root.winfo_rooty() + self.root.winfo_height())
            self.app.notebook.select(self.app.live_tab)
            self.root.update()
            for widget in (self.app.live_tree, self.app.live_details):
                self.assertTrue(widget.winfo_ismapped())
                self.assertGreater(widget.winfo_height(), 20)
                self.assertLessEqual(widget.winfo_rootx() + widget.winfo_width(),
                                     self.root.winfo_rootx() + self.root.winfo_width())
                self.assertLessEqual(widget.winfo_rooty() + widget.winfo_height(),
                                     self.root.winfo_rooty() + self.root.winfo_height())

    def test_live_suite_results_and_stop(self):
        import threading
        from modules.live_tests import LiveTestRunner
        self.app.operator.set('Lab / ticket')
        self.app.authorized.set(True)
        with patch('ui.messagebox.askyesno', return_value=True), patch('ui.threading.Thread'):
            self.app.start_suite()
        self.assertTrue(self.app.busy)
        self.app.stop_suite()
        self.assertTrue(self.app.cancel_run.is_set())
        cancel = threading.Event()
        cancel.set()
        run = LiveTestRunner().run('192.0.2.10', 'Lab / ticket', True, cancel)
        self.app.events.put(('suite', run))
        self.app._poll()
        self.assertFalse(self.app.busy)
        self.assertEqual(self.app.build_report()['live_test_run']['outcome'], 'cancelled')
        self.app.live_tree.selection_set('CIP-01')
        self.app._select_live_test()
        self.assertIn('not_run', self.app.live_details.get('1.0', 'end'))

    def test_close_during_run_waits_for_cleanup(self):
        self.app._set_busy(True)
        with patch('ui.messagebox.askyesno', return_value=True), patch.object(self.root, 'destroy') as destroy:
            self.app.close_window()
            self.assertTrue(self.app.cancel_run.is_set())
            self.assertTrue(self.app.closing)
            destroy.assert_not_called()
            self.app.events.put(('error', 'Cancelled before connection'))
            self.app._poll()
            destroy.assert_called_once()


if __name__ == '__main__':
    unittest.main()