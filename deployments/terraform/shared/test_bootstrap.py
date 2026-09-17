"""Execute the bootstrap against fake cloud transports and an isolated filesystem."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

TEMPLATE = Path(__file__).with_name('bootstrap.sh.tftpl').read_text()

class BootstrapTests(unittest.TestCase):
    def run_bootstrap(self, provider, bad_hash=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            mocks = root/'bin'; mocks.mkdir()
            payload = b'#!/bin/sh\nexit 0\n'
            key = '$HOME-secret"with\\escapes\nand-newline'
            settings = dict(provider=provider, region='test-region', secret='test-secret', client_id='test-client',
                            binaries={'amd64': {'url':'https://example.invalid/darkd','sha256': '0'*64 if bad_hash else hashlib.sha256(payload).hexdigest()},
                                      'arm64': {'url':'https://example.invalid/darkd','sha256': '0'*64 if bad_hash else hashlib.sha256(payload).hexdigest()}})
            # Only test rendering redirects filesystem paths; the production script
            # has no environment-controlled privileged destination override.
            script = TEMPLATE.replace('${settings}',base64.b64encode(json.dumps(settings).encode()).decode())
            for location in ['/etc/afterdark','/var/lib/afterdark','/var/log/afterdark','/run/afterdark','/usr/local/bin','/etc/systemd/system']:
                dest = root/location.lstrip('/'); dest.mkdir(parents=True,exist_ok=True)
                script = script.replace(location,str(dest))
            (root/'bootstrap.sh').write_text(script)
            mock = '''#!/usr/bin/env python3
import base64,json,os,sys
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as out: out.write(name+'\\n')
key=os.environ['TEST_KEY']
if name=='curl':
    if '-o' in args: Path(args[args.index('-o')+1]).write_bytes(base64.b64decode(os.environ['PAYLOAD']))
    elif any('/oauth2/token' in a or '/default/token' in a for a in args): print(json.dumps({'access_token':'test-token'}))
    elif any('secretmanager' in a for a in args): print(json.dumps({'payload':{'data':base64.b64encode(key.encode()).decode()}}))
    else: print(json.dumps({'value':key}))
elif name=='aws': print(json.dumps({'Parameter':{'Value':key}}))
elif name=='systemctl' and args==['is-active','--quiet','afterdark-darkd']: pass
'''
            for name in ['apt-get','curl','aws','systemctl']:
                p=mocks/name;p.write_text(mock);p.chmod(0o755)
            env=dict(os.environ,PATH=str(mocks)+os.pathsep+os.environ['PATH'],CALLS=str(root/'calls'),TEST_KEY=key,PAYLOAD=base64.b64encode(payload).decode())
            result=subprocess.run(['bash',str(root/'bootstrap.sh')],env=env,capture_output=True,text=True)
            if bad_hash:
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn('systemctl',(root/'calls').read_text())
                self.assertFalse((root/'etc/afterdark/darkd.yaml').exists())
            else:
                self.assertEqual(result.returncode,0,result.stderr)
                config=root/'etc/afterdark/darkd.yaml'
                credentials=root/'etc/afterdark/credentials.json'
                self.assertEqual(json.loads(credentials.read_text())['api_key'],key)
                self.assertEqual(credentials.stat().st_mode & 0o777,0o600)
                self.assertNotIn(key,config.read_text())
                self.assertEqual(config.stat().st_mode & 0o777,0o600)
                self.assertEqual((root/'usr/local/bin/afterdark-darkd').read_bytes(),payload)
                unit=(root/'etc/systemd/system/afterdark-darkd.service').read_text()
                self.assertIn(' run --config ',unit)
                self.assertIn('--remote Disabled',unit)
                self.assertEqual((root/'calls').read_text().count('systemctl'),4)

    def test_provider_bootstraps(self):
        for provider in ['aws','azure','gcp']:
            with self.subTest(provider=provider): self.run_bootstrap(provider)
    def test_invalid_digest_prevents_installation(self):
        self.run_bootstrap('aws',True)

if __name__=='__main__': unittest.main()
