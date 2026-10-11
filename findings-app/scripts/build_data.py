import csv,collections,re,json,sys
csv.field_size_limit(10**9)
OUT=sys.argv[2]
r=list(csv.reader(open(sys.argv[1],encoding='utf-8-sig')))
h=r[0]; rows=r[1:]
I={c:i for i,c in enumerate(h)}
g=lambda x,c:x[I[c]].strip()
P=lambda x,c:g(x,'Policy '+c)
N=len(rows)
def cnt(pred): return sum(1 for x in rows if pred(x))
leg=re.compile(r'\bXP\b|Windows 7|2008|2003|Vista|Windows 2000|Windows NT|Ubuntu 1[0-8]\.',re.I)
oscols=['Operating System','Mapped OTSM OS','Windows Version','OS Details','CCG Operating System','Cloud Data Exchange OS']
legacy=[]
for x in rows:
  for c in oscols:
    if leg.search(g(x,c)):
      legacy.append({'host':g(x,'Host'),'function':g(x,'Function') or 'Unknown','os':g(x,c),'segment':g(x,'Segment') or '(none)','purdue':g(x,'OT Purdue Level') or '—','ip':g(x,'IPv4 Address') or '—'});break
# dedupe exact
seen=set();L2=[]
for i,d in enumerate(legacy):
  k=(d['host'],d['ip'],d['segment'],d['function'])
  if k in seen: continue
  seen.add(k); d['id']=f"{d['host']} ({d['ip']})"; L2.append(d)
legacy=L2
weak=lambda x: any(s in P(x,'Telnet Credential Vuln')+P(x,'SSH Credential Vuln')+P(x,'SNMP Credential Vuln') for s in ['MATCH Commonly Used','MATCH Factory Default'])
weak_n=cnt(weak)
weak_unk=cnt(lambda x:'IRRESOLVED' in P(x,'Weak Credentials'))
clr=cnt(lambda x:P(x,'Cleartext Ports Open').startswith('MATCH'))
clr_unk=cnt(lambda x:P(x,'Cleartext Ports Open').startswith('IRRESOLVED'))
exposed=cnt(lambda x:g(x,'Cloud Data Exchange Risk Internet Exposure Indication')=='Yes')
crit=lambda x: any(k in P(x,'3.3.2.02 Host Criticality') for k in ['4 - High','5 - Critical'])
crit_n=cnt(crit); crit_nc=cnt(lambda x:crit(x) and g(x,'Compliance Status')=='Not Compliant')
comp=cnt(lambda x:g(x,'Compliance Status')=='Compliant'); ncomp=cnt(lambda x:g(x,'Compliance Status')=='Not Compliant')
os_unk=cnt(lambda x:g(x,'Operating System') in ('Unknown',''))
owner=cnt(lambda x:g(x,'User Name') or g(x,'Display Name'))
cmdb_in=cnt(lambda x:g(x,'Host Status in CMDB')=='Exists in CMDB'); cmdb_out=cnt(lambda x:g(x,'Host Status in CMDB')=='Does Not Exist in CMDB')
iot_unm=cnt(lambda x:'Investigate (Unmatch)' in P(x,'9.0.1 IoT Risk Assessment - CMDB Correlation'))
unrated=cnt(lambda x:P(x,'3.3.2.02 Host Criticality').startswith('UNMATCH'))
patch_crit=cnt(lambda x:P(x,'1.3.1.06 Windows Patch Compliance') in ('MATCH Critical Patches Missing','MATCH Important Patches Missing'))
patch_unk=cnt(lambda x:'NOT Validated' in P(x,'1.3.1.06 Windows Patch Compliance'))
fw=cnt(lambda x:'Non-Compliant' in P(x,'IoT Firmware Compliance (Non-Windows)'))
log4j=cnt(lambda x:P(x,'VR Apache Log4j')=='MATCH Unknown')
ot=lambda x:g(x,'OT Purdue Level')[:1] in ('0','1','2','3') and g(x,'OT Purdue Level')!=''
ot_out=cnt(lambda x:ot(x) and g(x,'Segment') not in ('Operational Technology',) and 'OT' not in g(x,'Segment'))
guest=cnt(lambda x:g(x,'Corporate/Guest Status')=='Unauthorized Guest')
vlan=cnt(lambda x:P(x,'Roaming Devices')=='MATCH Wired - improper VLAN')
vlan1=cnt(lambda x:g(x,'Switch Port VLAN')=='1')
multi=cnt(lambda x:P(x,'Multiple Hosts On Switch Port Audit')=='MATCH Multiple hosts on port')
untrusted=cnt(lambda x:P(x,'4.1.00 Trust Status')=='MATCH Untrusted devices')
notraffic=cnt(lambda x:P(x,'Traffic Visibility Audit')=='MATCH No Traffic Data')
av_bad=cnt(lambda x:P(x,'1.3.1.01 Antivirus Assessment Microsoft Defender') in ('MATCH Antivirus Running & Not Up To Date','MATCH Antivirus Installed & Not Running'))
av_all=cnt(lambda x:P(x,'1.3.1.01 Antivirus Assessment Microsoft Defender').startswith('MATCH'))
av_ok=cnt(lambda x:P(x,'1.3.1.01 Antivirus Assessment Microsoft Defender')=='MATCH Antivirus Running & Up to Date')
mde_high=cnt(lambda x:'Risk Score High' in P(x,'Endpoint risk score from Microsoft Defender for Endpoint'))
enc_bad=cnt(lambda x:P(x,'CUI System - Disk Encryption Assessment') in ('MATCH Disk Encryption Installed and Not Encrypted','MATCH Disk Encryption Not installed'))
enc_unk=cnt(lambda x:P(x,'CUI System - Disk Encryption Assessment')=='MATCH Disk Encryption Irresolvable')
enc_all=cnt(lambda x:P(x,'CUI System - Disk Encryption Assessment').startswith('MATCH'))
dadmin=cnt(lambda x:P(x,'Users L4-7 ID Mapping Segmentation')=='MATCH Domain Admin')
siem=cnt(lambda x:g(x,'Splunk: Send Update from CounterACT')=='Action completed' or g(x,'Send update to Sentinel')=='Action completed')
cs_bad=cnt(lambda x:P(x,'3.4.1 CrowdStrike Agent Hygiene') in ('MATCH CrowdStrike Agent Not Installed','MATCH CrowdStrike Agent Installed NOT Responsive'))
cs_all=cnt(lambda x:P(x,'3.4.1 CrowdStrike Agent Hygiene').startswith(('MATCH','UNMATCH')))
cs_ok=cnt(lambda x:P(x,'3.4.1 CrowdStrike Agent Hygiene')=='MATCH CrowdStrike Agent Running and Manageable by CounterACT')
win=cnt(lambda x:P(x,'1.1.01 Enterprise Discover')=='MATCH Windows')
win_managed=cnt(lambda x:P(x,'4.1.01 Managed Windows Devices')=='MATCH Managed Windows Device')
sccm=cnt(lambda x:P(x,'3.8.1 Windows Managed SCCM Client')=='MATCH Managed with SCCM Agent')
mde_on=cnt(lambda x:P(x,'Endpoint is onboarded at Microsoft Defender for Endpoint')=='MATCH Endpoint Onboarded')
sc_win=cnt(lambda x:g(x,'Windows SecureConnector Deployment Type') not in ('None',''))
dot1x=cnt(lambda x:g(x,'802.1x RADIUS Authentication State')=='RADIUS-Accepted')
wired=cnt(lambda x:P(x,'Campus Wired')=='MATCH Campus Wired')
creds_tested=N-weak_unk-cnt(lambda x:P(x,'Weak Credentials')=='NA')
summary=[
 ('total_hosts','Hosts in the export',N),('compliant','Compliant',comp),('noncompliant','Not compliant',ncomp),('na','No compliance result',N-comp-ncomp),
 ('legacy','Legacy OS hosts',len(legacy)),('weak_creds','Weak or default credentials confirmed',weak_n),('weak_unknown','Credentials never tested',weak_unk),
 ('exposed','Internet-exposed devices',exposed),('crit_high','High or Critical hosts',crit_n),('crit_high_nc','High or Critical hosts not compliant',crit_nc),
 ('cleartext','Telnet or FTP open (confirmed)',clr)]
summary=[{'metric':a,'label':b,'value':c} for a,b,c in summary]
F=[]
def f(id,pillar,finding,affected,unverified,sev,step,priority):
  F.append({'id':id,'pillar':pillar,'finding':finding,'affected':affected,'unverified':unverified,'severity':sev,'next_step':step,'priority':priority})
A='1. Asset classification';B='2. Patch & vulnerability';C='3. Segmentation & Zero Trust';D='4. Endpoint & monitoring'
f('legacy',A,'Legacy OS (XP, Vista, 7, 2003, 2008), mostly OT and medical',len(legacy),0,'Critical','Isolate in OT/medical enclaves, plan replacement, monitor passively',1)
f('os_unknown',A,'Operating system not identified',os_unk,0,'Medium','Enable deeper profiling or deploy SecureConnector to classify',3)
f('no_owner',A,'No owner or user recorded',N-owner,0,'Medium','Pull owner and department from CMDB/ServiceNow',3)
f('not_cmdb',A,'Not in CMDB',cmdb_out,iot_unm,'Medium','Onboard missing hosts; reconcile unmatched IoT records',3)
f('unrated',A,'No criticality rating',unrated,0,'Medium','Rate every asset; default OT and clinical to High',3)
f('weak_creds',B,'Weak or factory-default credentials confirmed',weak_n,weak_unk,'Critical','Rotate now on switches, routers, MRI and infusion pumps; test the rest',1)
f('exposed',B,'Reachable from the internet',exposed,0,'Critical','Remove internet routes or put behind firewall/VPN; investigate unknowns',1)
f('patch',B,'Windows critical or important patches missing',patch_crit,patch_unk,'High','Push critical patches; fix patch validation so status is known',2)
f('firmware',B,'Non-compliant IoT/OT firmware',fw,0,'High','Schedule vendor-approved firmware updates',2)
f('cleartext',B,'Telnet or FTP open',clr,clr_unk,'High','Disable Telnet/FTP/HTTP management; use SSH/HTTPS',2)
f('log4j',B,'Log4j status unknown',0,log4j,'Medium','Run Log4j checks or confirm hosts are out of scope',3)
f('ot_seg',C,'OT devices (Purdue 0–3) outside OT segments',ot_out,0,'High','Move to OT VLANs behind an industrial DMZ firewall',2)
f('guest',C,'Unauthorized guest devices on internal segments',guest,0,'High','Quarantine; require guest registration',2)
f('vlan',C,'Wired devices on the wrong VLAN',vlan,0,'Medium','Assign VLANs by classification',3)
f('vlan1',C,'Switch ports on default VLAN 1',vlan1,0,'Medium','Move ports off VLAN 1',3)
f('multi',C,'Several hosts behind one switch port',multi,0,'Medium','Check for unmanaged hubs or rogue switches',3)
f('untrusted',C,'Untrusted devices',untrusted,0,'Medium','Restrict access until classified and trusted',3)
f('traffic',C,'No traffic data for segmentation',0,notraffic,'Medium','Enable flow collection before writing allow-lists',3)
f('mde_high',D,'Defender for Endpoint risk score High',mde_high,0,'High','Investigate now; onboard all Windows to Defender for Endpoint',1)
f('av',D,'Defender antivirus out of date or not running',av_bad,0,'High','Force signature updates; restart stopped AV',2)
f('encryption',D,'Disk not encrypted',enc_bad,enc_unk,'High','Turn on BitLocker or FileVault',2)
f('admin_mfa',D,'Domain Admin sessions on endpoints; MFA not reported',dadmin,0,'High','Require MFA for admin and remote logins; vault admin accounts',2)
f('crowdstrike',D,'CrowdStrike agent missing or not responding',cs_bad,0,'Medium','Fix agent install and health',3)
f('siem',D,'Hosts not forwarded to a SIEM',N-siem,0,'Medium','Forward all hosts and policy events to Splunk/Sentinel',3)
C2=[]
def c(id,area,label,cov,tot,note):
  C2.append({'id':id,'area':area,'control':label,'covered':cov,'total':tot,'note':note})
c('os_id','Asset','OS identified',N-os_unk,N,'All hosts')
c('owner','Asset','Owner recorded',owner,N,'All hosts')
c('cmdb','Asset','In CMDB',cmdb_in,N,'All hosts')
c('creds','Patch','Credentials tested',creds_tested,N-cnt(lambda x:P(x,'Weak Credentials')=='NA'),'Hosts the credential policy evaluated')
c('patch_known','Patch','Patch status known',win_managed-patch_unk,win_managed,'Managed Windows hosts')
c('av_ok','Endpoint','Antivirus up to date',av_ok,av_all,'Windows hosts with Defender checked')
c('sccm','Endpoint','SCCM agent installed',sccm,win_managed,'Managed Windows hosts')
c('encrypted','Endpoint','Disk encryption confirmed',enc_all-enc_bad-enc_unk,enc_all,'Hosts the encryption policy evaluated')
c('sc','Endpoint','ForeScout agent (Windows)',sc_win,win,'Windows hosts')
c('mde','Endpoint','Onboarded to Defender for Endpoint',mde_on,win,'Windows hosts')
c('dot1x','Network','802.1X authenticated',dot1x,wired,'Campus wired hosts')
c('siem','Monitoring','Forwarded to SIEM',siem,N,'All hosts')
dev=collections.Counter(P(x,'1.1.01 Enterprise Discover').replace('MATCH ','') for x in rows if P(x,'1.1.01 Enterprise Discover').startswith('MATCH'))
devices=[{'type':k,'hosts':v} for k,v in dev.most_common()]
other=N-sum(dev.values()); devices.append({'type':'Not classified','hosts':other})
for name,data in [('summary',summary),('findings',F),('coverage',C2),('devices',devices),('legacy',legacy)]:
  json.dump(data,open(f'{OUT}/{name}.json','w'),indent=0)
print(json.dumps(summary)); print(json.dumps(C2)); print(devices); print(len(legacy))
for x in F: print(x['id'],x['affected'],x['unverified'])
