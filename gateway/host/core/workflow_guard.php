<?php
/* Private workflow admission/reductions. No CLI, public selector or grant API. */
declare(strict_types=1);
const WG_RUN='/run/reach-owner-mcp';
const WG_FENCE=WG_RUN.'/claim-fence.lock';
const WG_STATE=NX_ROOT.'/state/workflows';
const WG_RUNTIME=WG_STATE.'/runtime-installation.json';
const WG_ACCEPTANCE=WG_STATE.'/workflow-admission-acceptance.json';
const WG_APPS=['admin.py','admin_frontend.py','approval_portal.py','channel.py','deployment_policy.py','gateway.py','owner_network_model.py','private_api.py','public_limits.py','registry.py','requirements.lock','service.py','tool-catalog.json'];

function wg_need(bool $v,string $why):void{nx_need($v,$why);}
function wg_sync(string $dir):void{nx_path($dir,true,0700);$f=fopen($dir,'r');wg_need(is_resource($f),'workflow-sync-open');try{wg_need(function_exists('fsync')&&fsync($f),'workflow-sync');}finally{fclose($f);}}
function wg_init():void{nx_path(NX_ROOT.'/state',true,0700);nx_dir(WG_STATE);wg_sync(NX_ROOT.'/state');}
function wg_write(string $path,array $v):void{wg_need(dirname($path)===WG_STATE,'workflow-fixed-state-path');wg_init();nx_atomic($path,$v);wg_sync(WG_STATE);}
function wg_session_path(string $sid):string{return WG_STATE.'/session-'.hash('sha256',nx_id($sid)).'.json';}
function wg_scope(array $b):string{return hash('sha256',json_encode([$b['subject'],$b['vm_id'],$b['control_id'],$b['lease_id'],$b['gateway_epoch']],JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES));}
function wg_scope_end_path(array $b):string{return WG_STATE.'/scope-'.wg_scope($b).'.ended.json';}
function wg_stamp(int $pid):array{
 wg_need($pid>1&&(@lstat('/proc/'.$pid)['uid']??null)===0,'workflow-owner-process');$raw=file_get_contents('/proc/'.$pid.'/stat');wg_need(is_string($raw)&&strlen($raw)<=8192&&strrpos($raw,')')!==false,'workflow-owner-process');$fields=preg_split('/\s+/',trim(substr($raw,strrpos($raw,')')+1)));wg_need(count($fields)>19&&ctype_digit($fields[19])&&$fields[0]!=='Z','workflow-owner-process');return['pid'=>$pid,'created'=>$fields[19]];
}
function wg_fence_file():void{
 $s=@lstat(WG_RUN);wg_need(is_array($s)&&!is_link(WG_RUN)&&($s['mode']&0170000)===0040000&&$s['uid']===0&&$s['gid']===10008&&($s['mode']&07777)===0750,'workflow-fence-parent');
 $s=@lstat(WG_FENCE);wg_need(is_array($s)&&!is_link(WG_FENCE)&&($s['mode']&0170000)===0100000&&$s['uid']===0&&$s['gid']===10008&&($s['mode']&07777)===0640&&$s['nlink']===1,'workflow-fence-file');
}
function wg_fenced(callable $call):mixed{
 wg_fence_file();$before=lstat(WG_FENCE);$f=fopen(WG_FENCE,'rb');wg_need(is_resource($f),'workflow-fence-open');try{$opened=fstat($f);foreach(['dev','ino','mode','uid','gid','nlink']as$k)wg_need($before[$k]===$opened[$k],'workflow-fence-replaced');$end=hrtime(true)+2000000000;while(!flock($f,LOCK_EX|LOCK_NB)){wg_need(hrtime(true)<$end,'workflow-fence-busy');usleep(2000);}clearstatcache(true,WG_FENCE);$after=lstat(WG_FENCE);foreach(['dev','ino','mode','uid','gid','nlink']as$k)wg_need($after[$k]===$opened[$k],'workflow-fence-replaced');return$call();}finally{fclose($f);}
}
function wg_runtime():array{
 $raw=nx_read(WG_RUNTIME,32768);$v=nx_json($raw,32768);nx_fields($v,['version','image_id','app_sha256','code_sha256']);wg_need($v['version']===1,'workflow-runtime-version');wg_need(is_string($v['image_id'])&&str_starts_with($v['image_id'],'sha256:'),'workflow-image');nx_hex(substr($v['image_id'],7));
 $names=array_keys($v['app_sha256']);sort($names);$want=WG_APPS;sort($want);wg_need($names===$want,'workflow-app-inventory');foreach($v['app_sha256']as$sha)nx_hex($sha);
 $paths=['nexus_owner.php'=>NX_ROOT.'/runtime/nexus_owner.php','nexus_common.php'=>NX_ROOT.'/runtime/nexus_common.php','workflow_guard.php'=>NX_ROOT.'/runtime/workflow_guard.php','workflow_claim.py'=>NX_ROOT.'/runtime/workflow_claim.py','owner_broker.php'=>'/var/lib/reach-owner/broker/owner_broker.php'];$keys=array_keys($v['code_sha256']);sort($keys);$want=array_keys($paths);sort($want);wg_need($keys===$want,'workflow-code-inventory');foreach($paths as$k=>$p)wg_need(hash('sha256',nx_read($p))===nx_hex($v['code_sha256'][$k]),'workflow-code-changed');
 return['value'=>$v,'sha256'=>hash('sha256',$raw)];
}
function wg_workflow_verified():bool{
 try{$runtime=wg_runtime();$v=nx_json(nx_read(WG_ACCEPTANCE,32768),32768);nx_fields($v,['version','runtime_installation_sha256','owner_browser_decision_path_verified','release_fence_verified','end_retry_verified','revoke_generation_verified','restart_fence_verified']);wg_need($v['version']===1&&$v['runtime_installation_sha256']===$runtime['sha256'],'workflow-acceptance-binding');foreach(['owner_browser_decision_path_verified','release_fence_verified','end_retry_verified','revoke_generation_verified','restart_fence_verified']as$k)wg_need($v[$k]===true,'workflow-native-acceptance-required');return true;}catch(Throwable $ignored){return false;}
}
function wg_attestation():array{
 $path='/var/lib/reach/reach-gateway/runtime/config/runtime-attestation.json';for($at=$path;;$at=dirname($at)){$s=@lstat($at);wg_need(is_array($s)&&!is_link($at)&&($s['mode']&0170000)===($at===$path?0100000:0040000),'workflow-runtime-ancestry');if(in_array($at,['/mnt/cache','/mnt/cache/appdata'],true))wg_need($s['uid']===99&&$s['gid']===100&&($s['mode']&07777)===0777,'workflow-unraid-boundary');else wg_need($s['uid']===0&&($s['mode']&0022)===0,'workflow-runtime-protection');if($at===$path)wg_need($s['nlink']===1&&$s['size']>0&&$s['size']<=262144,'workflow-runtime-bound');if($at==='/')break;}$before=lstat($path);$f=fopen($path,'rb');wg_need(is_resource($f),'workflow-runtime-open');try{$opened=fstat($f);foreach(['dev','ino','mode','uid','gid','size','mtime','ctime','nlink']as$k)wg_need($before[$k]===$opened[$k],'workflow-runtime-replaced');$raw=stream_get_contents($f,262145);wg_need(is_string($raw)&&strlen($raw)===$opened['size'],'workflow-runtime-read');}finally{fclose($f);}clearstatcache(true,$path);$after=lstat($path);foreach(['dev','ino','mode','uid','gid','size','mtime','ctime','nlink']as$k)wg_need($before[$k]===$after[$k],'workflow-runtime-replaced');$v=nx_json($raw);nx_hex($v['container_id']??null);wg_need(($v['host_boot_id']??null)===trim(file_get_contents('/proc/sys/kernel/random/boot_id')),'workflow-current-host-boot');return['value'=>$v,'sha256'=>hash('sha256',$raw)];
}
function wg_verify_unlocked(array $binding):array{
 $r=wg_runtime();$v=$r['value'];$attestation=wg_attestation();$cid=$attestation['value']['container_id'];wg_need(($attestation['value']['image_id']??null)===$v['image_id'],'workflow-attested-image');
 $format='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"user":{{json .Config.User}}}';$i=nx_run(['/usr/bin/docker','inspect','--format',$format,$cid],'',2,4096);wg_need($i['exit']===0&&$i['err']==='','workflow-container-observation');$i=nx_json(trim($i['out']),4096);wg_need($i===['id'=>$cid,'image'=>$v['image_id'],'running'=>true,'user'=>'10008:10008'],'workflow-current-container');
 $module=base64_encode(nx_read(NX_ROOT.'/runtime/workflow_claim.py'));$pins=base64_encode(nx_bytes($v['app_sha256']));$code="import base64,json,os,sqlite3,stat,sys\nns={}\nexec(compile(base64.b64decode('".$module."'),'pinned-workflow-predicate','exec'),ns)\npins=json.loads(base64.b64decode('".$pins."'))\n";
 $code.= <<<'PY'
import hashlib
assert os.getuid()==os.getgid()==10008
sys.path.insert(0,'/app')
import admin
for name,pin in pins.items():
 assert hashlib.sha256(admin.protected_bytes('/app/'+name,524288)).hexdigest()==pin
context=admin.deployment_context(admin.protected_file,admin.protected_bytes)
for p,d in (('/state',True),('/state/registry.sqlite3',False)):
 s=os.lstat(p)
 assert (stat.S_ISDIR(s.st_mode) if d else stat.S_ISREG(s.st_mode)) and s.st_uid in (0,10008) and s.st_gid in (0,10008) and not s.st_mode&0o002 and (d or s.st_nlink==1)
db=sqlite3.connect('file:/state/registry.sqlite3?mode=ro',uri=True,isolation_level=None,timeout=.2)
try:
 db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
 binding=json.load(sys.stdin)
 result=ns['verify'](db,binding,lambda vm:admin.persistent_context(vm,context=context))
 print(json.dumps(result,sort_keys=True,separators=(',',':')))
finally:
 if db.in_transaction:db.execute('ROLLBACK')
 db.close()
PY;
 $reply=nx_run(['/usr/bin/docker','exec','-i','--user','10008:10008',$cid,'python','-I','-B','-c',$code],nx_bytes($binding),2,32768);wg_need($reply['exit']===0&&$reply['err']==='','workflow-live-claim-refused');wg_need(wg_attestation()['sha256']===$attestation['sha256'],'workflow-runtime-changed-during-verification');$out=nx_json(trim($reply['out']),32768);wg_need(($out['scope']??null)===wg_scope($binding),'workflow-live-scope');$out['runtime_sha256']=$r['sha256'];wg_need(microtime(true)<min($out['lease_expires_at'],$out['reservation_expires_at']),'workflow-expired-during-verification');return$out;
}
function wg_verify(array $binding):array{return wg_fenced(static fn()=>wg_verify_unlocked($binding));}
function wg_start_intent(string $sid,array $binding,int $revision):void{wg_write(WG_STATE.'/start-'.hash('sha256',nx_id($sid)).'.json',['version'=>1,'session_id'=>$sid,'binding'=>$binding,'revision'=>$revision,'console'=>wg_stamp(posix_getpid()),'cancelled'=>false]);}
function wg_cancel_start(string $sid):void{$p=WG_STATE.'/start-'.hash('sha256',nx_id($sid)).'.json';$v=nx_json(nx_read($p,8192),8192);$v['cancelled']=true;wg_write($p,$v);}
function wg_register(string $sid,string $generation,array $verified,int $revision):void{
 wg_need(str_starts_with($sid,'mcp-'),'workflow-session-prefix');nx_hex($generation,32);wg_need(!file_exists(wg_scope_end_path($verified['binding'])),'workflow-scope-ended');$p=wg_session_path($sid);wg_need(!file_exists($p),'workflow-session-reuse');wg_write($p,['version'=>1,'session_id'=>$sid,'generation'=>$generation,'binding'=>$verified['binding'],'anchor'=>$verified['anchor'],'runtime_sha256'=>$verified['runtime_sha256'],'revision'=>$revision,'console'=>wg_stamp(posix_getpid()),'ended'=>false,'permission_mode'=>'ask_each']);
}
function wg_session(string $sid,string $gen):array{$v=nx_json(nx_read(wg_session_path($sid),32768),32768);wg_need(($v['version']??null)===1&&($v['session_id']??null)===$sid&&($v['generation']??null)===$gen,'workflow-session-association');return$v;}
function wg_allow(string $sid,string $gen,int $revision):void{$v=wg_session($sid,$gen);wg_need(!$v['ended']&&$v['revision']===$revision&&wg_workflow_verified()&&!file_exists(wg_scope_end_path($v['binding'])),'workflow-grant-not-verified');$v['permission_mode']='workflow';wg_write(wg_session_path($sid),$v);}
function wg_capture_operation(string $sid,string $gen,string $operation,string $sha,int $revision,bool $workflow):void{
 $v=wg_session($sid,$gen);wg_need(!$v['ended']&&$v['revision']===$revision,'workflow-operation-revision');if($workflow)wg_need($v['permission_mode']==='workflow'&&wg_workflow_verified(),'workflow-owner-choice-required');nx_hex($operation,32);nx_hex($sha);$path=WG_STATE.'/operation-'.$operation.'.json';wg_need(!file_exists($path),'workflow-operation-reuse');wg_write($path,['version'=>1,'session_id'=>$sid,'generation'=>$gen,'operation_id'=>$operation,'request_sha256'=>$sha,'revision'=>$revision,'workflow'=>$workflow]);
}
function wg_dispatch(string $sid,string $gen,string $operation,string $sha,array $console,callable $spawn):mixed{
 // Only broker-origin sessions use this gate. Private owner-console behavior is
 // unchanged; all mcp-* sessions fail closed without a protected association.
 if(!str_starts_with($sid,'mcp-'))return$spawn();
 return wg_fenced(static function()use($sid,$gen,$operation,$sha,$console,$spawn){$v=wg_session($sid,$gen);wg_need(!$v['ended']&&$v['console']===$console&&wg_stamp($console['pid'])===$console&&!file_exists(wg_scope_end_path($v['binding'])),'workflow-ended-before-dispatch');$op=nx_json(nx_read(WG_STATE.'/operation-'.nx_hex($operation,32).'.json',8192),8192);wg_need(($op['session_id']??null)===$sid&&($op['generation']??null)===$gen&&($op['operation_id']??null)===$operation&&($op['request_sha256']??null)===$sha&&($op['revision']??null)===$v['revision'],'workflow-operation-association');if($op['workflow'])wg_need($v['permission_mode']==='workflow'&&wg_workflow_verified(),'workflow-grant-revoked');$now=wg_verify_unlocked($v['binding']);wg_need($now['anchor']===$v['anchor']&&$now['runtime_sha256']===$v['runtime_sha256'],'workflow-authority-changed');wg_need(microtime(true)<min($now['lease_expires_at'],$now['reservation_expires_at']),'workflow-expired-at-dispatch');return$spawn();});
}
function wg_end_generation(string $sid,string $gen,string $reference):void{
 $v=wg_session($sid,$gen);$v['ended']=true;$v['permission_mode']='ask_each';wg_write(wg_session_path($sid),$v);$p=WG_STATE.'/end-'.hash('sha256',$sid.'|'.$gen).'.json';if(!file_exists($p))wg_write($p,['version'=>1,'session_id'=>$sid,'generation'=>$gen,'reference'=>$reference,'acknowledged'=>false]);
 // Barrier: return only after any earlier admission critical section completed.
 wg_fenced(static fn()=>true);
}
function wg_end_scope(array $binding,string $reference):void{wg_write(wg_scope_end_path($binding),['version'=>1,'scope'=>wg_scope($binding),'ended'=>true]);foreach(glob(WG_STATE.'/session-*.json')?:[]as$p){$v=nx_json(nx_read($p,32768),32768);if(wg_scope($v['binding'])===wg_scope($binding))wg_end_generation($v['session_id'],$v['generation'],$reference);}wg_fenced(static fn()=>true);}
function wg_revoke_scope(array $binding,string $reference):void{foreach(glob(WG_STATE.'/session-*.json')?:[]as$p){$v=nx_json(nx_read($p,32768),32768);if(wg_scope($v['binding'])===wg_scope($binding))wg_end_generation($v['session_id'],$v['generation'],$reference);}wg_fenced(static fn()=>true);}
function wg_pending_ends():array{
 // Recover a tombstone/outbox crash gap and a lost start acknowledgement using
 // only the exact old Core binding; never start/approve/execute from this sweep.
 foreach(glob(WG_STATE.'/session-*.json')?:[]as$p){$v=nx_json(nx_read($p,32768),32768);try{$live=wg_stamp($v['console']['pid'])===$v['console'];}catch(Throwable $ignored){$live=false;}if(!$live&&!$v['ended']){$v['ended']=true;$v['permission_mode']='ask_each';wg_write($p,$v);}if($v['ended']){$end=WG_STATE.'/end-'.hash('sha256',$v['session_id'].'|'.$v['generation']).'.json';if(!file_exists($end))wg_write($end,['version'=>1,'session_id'=>$v['session_id'],'generation'=>$v['generation'],'reference'=>'Recover durable ended workflow generation','acknowledged'=>false]);}}
 foreach(glob(WG_STATE.'/start-*.json')?:[]as$p){$v=nx_json(nx_read($p,8192),8192);if(file_exists(wg_session_path($v['session_id'])))continue;try{$live=wg_stamp($v['console']['pid'])===$v['console'];}catch(Throwable $ignored){$live=false;}if($live&&!$v['cancelled'])continue;$binding=NX_ROOT.'/state/sessions/'.hash('sha256',$v['session_id']).'.json';if(!file_exists($binding))continue;$b=nx_json(nx_read($binding,8192),8192);wg_need(($b['session_id']??null)===$v['session_id']&&($b['console']??null)===$v['console'],'workflow-orphan-start-binding');nx_hex($b['generation'],32);$end=WG_STATE.'/end-'.hash('sha256',$v['session_id'].'|'.$b['generation']).'.json';if(!file_exists($end))wg_write($end,['version'=>1,'session_id'=>$v['session_id'],'generation'=>$b['generation'],'reference'=>'Reduce exact orphaned workflow start','acknowledged'=>false]);}
 $out=[];foreach(glob(WG_STATE.'/end-*.json')?:[]as$p){$v=nx_json(nx_read($p,8192),8192);wg_need(($v['version']??null)===1&&is_bool($v['acknowledged']??null),'workflow-end-record');if(!$v['acknowledged']){$v['path']=$p;$out[]=$v;}}return$out;
}
function wg_ack_end(array $record,array $reply):void{wg_need(($reply['session']['version']??null)===1&&($reply['session']['active']??true)===false&&($reply['session']['session_id']??null)===$record['session_id']&&($reply['session']['generation']??null)===$record['generation'],'workflow-end-ack');$v=nx_json(nx_read($record['path'],8192),8192);wg_need($v['session_id']===$record['session_id']&&$v['generation']===$record['generation'],'workflow-end-record-changed');$v['acknowledged']=true;wg_write($record['path'],$v);}
