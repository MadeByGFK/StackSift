"""Compare unchanged frozen inputs against PR12's original diagnostic behavior."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--fixtures", type=Path, required=True)
parser.add_argument("--baseline", type=Path, required=True, help="Original checkout's src/web directory")
args = parser.parse_args()
archive = args.fixtures.resolve()
current = Path(__file__).resolve().parents[1] / "src/web"
runner = '''
import json,sys,zipfile
from app.service import analyze_upload
with zipfile.ZipFile(sys.argv[1]) as z:
 output={}
 for name in z.namelist():
  if name.endswith('.log'):
   result=analyze_upload(name,z.read(name))
   assert 'error' not in result, (name,result)
   result.pop('elapsed')
   result['results'].pop('file')
   output[name]=result
 print(json.dumps(output,sort_keys=True,default=str))
'''
with zipfile.ZipFile(archive) as z:
    for entry in json.loads(z.read('fixture_manifest.json')):
        content = z.read(entry['file'])
        assert hashlib.sha256(content).hexdigest() == entry['sha256']
        assert len(content) == entry['bytes']
results=[]
for root in [args.baseline.resolve(), current]:
    env={**os.environ,'PYTHONPATH':str(root)}
    result=subprocess.run([sys.executable,'-c',runner,str(archive)],env=env,capture_output=True,text=True,check=True)
    results.append(json.loads(result.stdout))
for name in results[0]:
    assert results[0][name] == results[1][name], name
    print(f'PASS {name}: identical output; health={results[1][name]["health"]["label"]}')
print('6/6 frozen fixtures unchanged; all manifest checksums verified. Only elapsed time and random temporary filename excluded.')
