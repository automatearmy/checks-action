import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


class RunnerStorageTests(unittest.TestCase):
    def test_container_runner_scan_uses_paths_shared_with_docker_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            shared = root / 'shared'
            workspace = shared / 'project'
            runner_temp = shared / '_temp'
            binaries = root / 'bin'
            for directory in (workspace, runner_temp, binaries):
                directory.mkdir(parents=True)
            # Emulate a host daemon that can only bind the runner's shared tree.
            docker = binaries / 'docker'
            docker.write_text('#!' + sys.executable + '\n' + textwrap.dedent('''\
                import json, os, pathlib, stat, sys
                args = sys.argv[1:]
                mounts = {}
                for index, arg in enumerate(args):
                    if arg == '--mount':
                        options = dict(item.split('=', 1) for item in args[index + 1].split(',') if '=' in item)
                        source = pathlib.Path(options['src']).resolve()
                        shared = pathlib.Path(os.environ['TEST_SHARED_ROOT']).resolve()
                        if shared != source and shared not in source.parents:
                            sys.exit('Docker host cannot access bind source: ' + str(source))
                        assert source.is_dir()
                        mounts[options['dst']] = source
                for destination in ('/reports', '/tmp/trivy-cache'):
                    assert stat.S_IMODE(mounts[destination].stat().st_mode) == 0o700
                filename = pathlib.Path(args[args.index('--output') + 1]).name
                (mounts['/reports'] / filename).write_text(json.dumps({'Results': []}))
                '''))
            docker.chmod(0o700)
            env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ['PATH'],
                       RUNNER_TEMP=str(runner_temp), GITHUB_WORKSPACE=str(workspace),
                       TEST_SHARED_ROOT=str(shared))
            for key in ('GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY'):
                env.pop(key, None)
            scanner = Path(__file__).resolve().parents[1] / 'scripts/checks.py'
            result = subprocess.run([sys.executable, str(scanner), '--upload', 'false'],
                                    cwd=workspace, env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            reports = list(runner_temp.glob('aarmy-checks-*'))
            self.assertEqual(len(reports), 1)
            summary = json.loads((reports[0] / 'summary.json').read_text())
            self.assertFalse(summary['uploaded'])
            self.assertEqual(summary['findings']['vulnerabilities'], {})


if __name__ == '__main__':
    unittest.main()
