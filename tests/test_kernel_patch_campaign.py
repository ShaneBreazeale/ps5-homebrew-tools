"""Evidence and coverage for a finite, host-only fault-containment experiment."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'host'))
import kernel_patch_campaign as experiment


class CampaignTests(unittest.TestCase):
    def test_full_grid_uses_real_core_and_records_reproducible_inputs(self):
        report = experiment.campaign(shlex.split(os.environ.get('HOST_CC', 'cc')))
        self.assertEqual(report['status'], 'passed', report)
        self.assertEqual(report['scope'], 'host_simulation')
        self.assertFalse(report['console_validated'])
        self.assertEqual(report['compiler']['exit_status'], 0)
        self.assertEqual(report['compile']['exit_status'], 0)
        self.assertEqual(report['run']['exit_status'], 0)
        self.assertEqual(report['source_sha256'], report['source_sha256_after'])
        for name, digest in report['source_sha256'].items():
            self.assertEqual(digest, hashlib.sha256((ROOT / name).read_bytes()).hexdigest())
        result = report['result']
        self.assertEqual(result['cases'], sum(result['scenarios'].values()))
        self.assertEqual(result['scenarios']['control'], 64 * 3)
        self.assertEqual(result['scenarios']['primary_short'], 3 * sum(range(1, 65)))
        self.assertEqual(result['scenarios']['primary_error'], 3 * sum(range(2, 66)))
        self.assertEqual(result['counterexamples'], 0)

    def test_compile_failure_is_saved_as_failure_without_a_fake_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            compiler = folder / 'failing-compiler.py'
            compiler.write_text('import sys\n'
                                'if "--version" in sys.argv:\n print("intentional compiler fixture")\n sys.exit(0)\n'
                                'print("intentional compile failure",file=sys.stderr)\nsys.exit(37)\n')
            output = folder / 'failed-trial.json'
            environment = {**os.environ, 'HOST_CC': shlex.join([sys.executable, str(compiler)])}
            command = [sys.executable, str(ROOT / 'host/kernel_patch_campaign.py'), '--output', str(output)]
            run = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=15)
            self.assertEqual(run.returncode, 1, run.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report['status'], 'compile_failed')
            self.assertEqual(report['compile']['exit_status'], 37)
            self.assertIn('intentional compile failure', report['compile']['stderr'])
            self.assertIsNone(report['result'])
            self.assertNotIn('run', report)
            before = output.read_bytes()
            refused = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=15)
            self.assertEqual(refused.returncode, 2)
            self.assertEqual(output.read_bytes(), before)

    def test_missing_compiler_is_a_failed_observation(self):
        report = experiment.campaign(['/does-not-exist/kernel-study-compiler'])
        self.assertEqual(report['status'], 'compiler_unavailable')
        self.assertIsNone(report['result'])
        self.assertIsNone(report['compiler']['exit_status'])
        self.assertFalse(report['console_validated'])

    def test_campaign_detects_deliberately_broken_rollback_and_false_restoration(self):
        # Sensitivity controls operate only on disposable source copies. A green
        # campaign is useful only if it also rejects known unsafe behavior.
        changes = (
            ('if (r.status || q.operation == KP_EXERCISE) kp_restore(e, &q, &r);',
             'if (!r.status && q.operation == KP_EXERCISE) kp_restore(e, &q, &r);',
             'scenario=primary_short'),
            ('if (!kp_snapshot(e, r) || r->restore_error || memcmp(r->preimage, r->final, q->length)) goto failed;',
             'if (!kp_snapshot(e, r)) goto failed;', 'scenario=restore_short'),
        )
        for original, replacement, symptom in changes:
            with self.subTest(symptom=symptom), tempfile.TemporaryDirectory() as tmp:
                folder = Path(tmp)
                for name in experiment.INPUTS[:-1]:
                    target = folder / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / name, target)
                core = folder / 'residents/patch/patch.h'
                source = core.read_text()
                self.assertEqual(source.count(original), 1)
                core.write_text(source.replace(original, replacement))
                executable = folder / 'known-bad'
                subprocess.run([*shlex.split(os.environ.get('HOST_CC', 'cc')), *experiment.FLAGS,
                                str(folder / 'tests/kernel_patch_campaign.c'), '-o', str(executable)],
                               check=True, capture_output=True, text=True, timeout=30)
                observed = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
                self.assertEqual(observed.returncode, 1)
                self.assertIn('counterexample:', observed.stderr)
                self.assertIn(symptom, observed.stderr)
                self.assertEqual(observed.stdout, '')


if __name__ == '__main__':
    unittest.main()
