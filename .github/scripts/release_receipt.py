"""Persist a non-secret release receipt so repository readers can verify publication."""
import base64,json,os,subprocess
repo=os.environ['GITHUB_REPOSITORY'];version=os.environ['RELEASE_TAG']
def api(path,payload=None):
 args=['gh','api',path]
 if payload is not None:args+=['--method','PUT','--input','-']
 p=subprocess.run(args,input=json.dumps(payload) if payload is not None else None,capture_output=True,text=True,check=True)
 return json.loads(p.stdout)
receipt={'version':version,'commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'workflow_run_id':os.environ['GITHUB_RUN_ID'],'native_result':os.environ['NATIVE_RESULT'],'release_result':os.environ['RELEASE_RESULT']}
if receipt['release_result']=='success':
 release=api('repos/'+repo+'/releases/tags/'+version)
 receipt.update(published=not release['draft'],url=release['html_url'],assets=[{k:a.get(k) for k in ('name','size','digest','browser_download_url')} for a in release['assets']])
else:receipt['published']=False
path='repos/'+repo+'/contents/.github/release-input/release-status-'+version+'.json'
payload={'message':'Record '+version+' release verification','content':base64.b64encode((json.dumps(receipt,indent=2)+'\n').encode()).decode()}
try:payload['sha']=api(path)['sha']
except subprocess.CalledProcessError:pass
api(path,payload)
print(json.dumps(receipt,indent=2))
