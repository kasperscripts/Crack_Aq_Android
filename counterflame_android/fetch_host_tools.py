from pathlib import Path
import argparse,hashlib,json,urllib.request,zipfile,io
p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args();root=Path(__file__).parent;v=json.loads((root/'host-tool-versions.json').read_text());a.output.mkdir(parents=True,exist_ok=True)
def get(url,digest):
 with urllib.request.urlopen(url,timeout=120) as r:data=r.read()
 assert hashlib.sha256(data).hexdigest()==digest;return data
(a.output/'json.jar').write_bytes(get(v['json_jar_url'],v['json_jar_sha256']))
raw=get(v['enjarify_archive_url'],v['enjarify_archive_sha256'])
with zipfile.ZipFile(io.BytesIO(raw)) as z:
 for name in z.namelist():assert '..' not in Path(name).parts and not Path(name).is_absolute()
 z.extractall(a.output)
print(a.output/('enjarify-'+v['enjarify_commit']))
