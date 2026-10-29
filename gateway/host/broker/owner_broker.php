<?php
/* Private Nexus host broker. The gateway's framework-sealed native human
 * elicitation is the approval issuer; no public caller controls these fields.
 * Only the UDS is mounted in the unprivileged gateway, never keys or Docker. */
declare(strict_types=1);
ini_set('display_errors','0');ini_set('log_errors','0');umask(0077);
const MB_ROOT='/var/lib/reach-owner/broker';
const MB_CORE='/var/lib/reach-owner/core';
const MB_CORE_MANIFEST='0000000000000000000000000000000000000000000000000000000000000000';
const MB_RUN='/run/reach-owner-mcp';
const MB_SOCKET=MB_RUN.'/owner.sock';
const MB_PEER_UID=10008;
const MB_WIRE=262144;
function mb_need(bool $v,string $why):void{if(!$v)throw new RuntimeException($why);}
function mb_fields(array $v,array $keys):void{$a=array_keys($v);sort($a);sort($keys);mb_need($a===$keys,'broker-request-fields');}
function mb_bytes(array $v):string{return json_encode($v,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);}
function mb_json(string $raw):array{mb_need(strlen($raw)<=MB_WIRE,'broker-wire-bound');$v=json_decode($raw,true,32,JSON_THROW_ON_ERROR);mb_need(is_array($v),'broker-json-object');return $v;}
function mb_hex(mixed $v,int $n=32):string{mb_need(is_string($v)&&(bool)preg_match('/^[a-f0-9]{'.$n.'}$/D',$v),'broker-hex-field');return $v;}
function mb_reference(mixed $v):string{mb_need(is_string($v)&&strlen($v)>0&&strlen($v)<=1024&&!preg_match('/[\x00-\x1f\x7f]/',$v),'broker-approval-reference');return $v;}
function mb_binding(array $v,float $now,bool $live=true):array{
 mb_fields($v,['subject','vm_id','control_id','lease_id','gateway_epoch','expires_at']);
 mb_need(is_string($v['subject'])&&(bool)preg_match('/^[1-9][0-9]{0,19}$/D',$v['subject'])&&in_array($v['vm_id'],['vm-alpha','vm-beta','vm-gamma'],true),'broker-binding-owner');
 foreach(['control_id','lease_id','gateway_epoch']as$k)mb_hex($v[$k]);
 mb_need((is_int($v['expires_at'])||is_float($v['expires_at']))&&is_finite((float)$v['expires_at'])&&$v['expires_at']>0&&$v['expires_at']<=$now+600,'broker-binding-expiry');
 if($live)mb_need($v['expires_at']>$now,'broker-workflow-expired');return $v;
}
function mb_scope(array $v):string{return hash('sha256',mb_bytes([$v['subject'],$v['vm_id'],$v['control_id'],$v['lease_id'],$v['gateway_epoch']]));}
function mb_path(string $path,bool $directory=false):void{for($at=$path;;$at=dirname($at)){$s=@lstat($at);mb_need(is_array($s)&&!is_link($at)&&($s['mode']&0170000)===($at===$path&&!$directory?0100000:0040000)&&$s['uid']===0&&$s['gid']===0&&($s['mode']&0022)===0,'protected-broker-path');if($at===$path&&!$directory)mb_need($s['nlink']===1,'protected-broker-file');if($at==='/')break;}}
function mb_read(string $path,int $maximum=262144):string{mb_path($path);$s=lstat($path);mb_need($s['size']<=$maximum,'broker-source-bound');$raw=file_get_contents($path);mb_need(is_string($raw)&&strlen($raw)===$s['size'],'broker-source-read');return $raw;}
function mb_new(string $path,string $raw):void{mb_path(dirname($path),true);mb_need(!file_exists($path)&&!is_link($path),'broker-file-already-exists');$f=fopen($path,'x+b');mb_need(is_resource($f),'broker-file-create');try{mb_need(chown($path,0)&&chgrp($path,0)&&chmod($path,0600)&&fwrite($f,$raw)===strlen($raw)&&fflush($f),'broker-file-write');if(function_exists('fsync'))mb_need(fsync($f),'broker-file-sync');}finally{fclose($f);}mb_need(mb_read($path,max(1,strlen($raw)))===$raw,'broker-file-verification');}
function mb_core_verify():void{mb_need(hash('sha256',mb_read(MB_CORE.'/runtime/runtime-files.json',16384))===MB_CORE_MANIFEST,'broker-core-release-changed');$m=mb_json(mb_read(MB_CORE.'/runtime/runtime-files.json',16384));foreach($m['files']as$name=>$sha){mb_need((bool)preg_match('/^[A-Za-z0-9_.-]+$/D',$name),'broker-core-file');mb_need(hash('sha256',mb_read(MB_CORE.'/runtime/'.$name))===$sha,'broker-core-file-changed');}}
function mb_runtime_verify():void{
 mb_need(PHP_SAPI==='cli'&&posix_geteuid()===0&&strtolower(gethostname())==='reach-host','nexus-root-broker-required');mb_path(MB_ROOT,true);mb_path(__FILE__);
 $m=mb_json(mb_read(MB_ROOT.'/broker-files.json',16384));mb_fields($m,['version','files']);mb_need(($m['version']??null)===1&&array_keys($m['files'])===['owner_broker.php','peercred.pl','start-owner-broker.sh'],'broker-runtime-inventory');
 foreach($m['files']as$name=>$sha)mb_need(hash('sha256',mb_read(MB_ROOT.'/'.$name))===$sha,'broker-runtime-pin');
 mb_need(extension_loaded('sockets')&&function_exists('socket_import_stream'),'linux-unix-sockets-required');mb_vendor_binary('/usr/bin/perl');mb_core_verify();
}
function mb_vendor_regular(string $path):void{for($at=$path;;$at=dirname($at)){$s=@lstat($at);mb_need(is_array($s)&&!is_link($at)&&($s['mode']&0170000)===($at===$path?0100000:0040000)&&$s['uid']===0&&$s['gid']===0&&($s['mode']&0022)===0,'protected-peer-runtime');if($at==='/')break;}}
function mb_perl_alias_target(string $path,string $target):string{
 mb_need($path==='/usr/bin/perl'&&preg_match('~^(?:/usr/bin/)?(perl[0-9][A-Za-z0-9._+-]{0,63})$~D',$target,$match)===1,'controlled-perl-vendor-alias');return '/usr/bin/'.$match[1];
}
function mb_vendor_binary(string $path):string{
 $before=@lstat($path);mb_need(is_array($before),'protected-peer-runtime');if(!is_link($path)){mb_vendor_regular($path);return $path;}
 // Only this vendor alias may be a symlink. Never apply this exception to
 // broker/helper/source/state files or to an arbitrary executable path.
 mb_path(dirname($path),true);mb_need($before['uid']===0&&$before['gid']===0&&($before['mode']&0170000)===0120000&&$before['nlink']===1,'protected-peer-runtime');$link=readlink($path);mb_need(is_string($link),'controlled-perl-vendor-alias');$target=mb_perl_alias_target($path,$link);mb_vendor_regular($target);mb_need(realpath($path)===$target,'controlled-perl-vendor-target');
 clearstatcache(true,$path);$after=lstat($path);foreach(['dev','ino','mode','uid','gid','nlink','mtime','ctime']as$key)mb_need($after[$key]===$before[$key],'changed-perl-vendor-alias');mb_need(readlink($path)===$link,'changed-perl-vendor-alias');return $target;
}
function mb_peer_credentials($connection,?string $helper=null,bool $forcePerl=false):array{
 if(!$forcePerl&&defined('SO_PEERCRED')){try{$socket=@socket_import_stream($connection);$v=$socket===false?false:@socket_get_option($socket,SOL_SOCKET,constant('SO_PEERCRED'));if(is_array($v)&&is_int($v['pid']??null)&&is_int($v['uid']??null)&&is_int($v['gid']??null)&&$v['pid']>0&&$v['uid']>=0&&$v['gid']>=0)return $v;}catch(Throwable $ignored){}}
 $path=$helper??MB_ROOT.'/peercred.pl';mb_path($path);$perl=mb_vendor_binary('/usr/bin/perl');
 $p=proc_open([$perl,$path],[0=>['file','/dev/null','r'],1=>['pipe','w'],2=>['pipe','w'],3=>$connection],$pipes,'/',['PATH'=>'/usr/bin:/bin','LANG'=>'C','LC_ALL'=>'C'],['bypass_shell'=>true]);mb_need(is_resource($p),'peer-helper-start');foreach($pipes as$f)stream_set_blocking($f,false);$out='';$err='';$exit=-1;$deadline=microtime(true)+1;
 try{do{$out.=stream_get_contents($pipes[1]);$err.=stream_get_contents($pipes[2]);mb_need(strlen($out)<=128&&strlen($err)<=1024,'peer-helper-output');$s=proc_get_status($p);if(!$s['running']){$exit=$s['exitcode'];break;}mb_need(microtime(true)<$deadline,'peer-helper-timeout');usleep(1000);}while(true);$out.=stream_get_contents($pipes[1]);$err.=stream_get_contents($pipes[2]);}
 finally{$s=proc_get_status($p);if($s['running'])proc_terminate($p,9);foreach($pipes as$f)fclose($f);$closed=proc_close($p);}if($exit<0)$exit=$closed;
 mb_need($exit===0&&$err===''&&preg_match('/^([1-9][0-9]{0,9}) ([0-9]{1,10}) ([0-9]{1,10})\n$/D',$out,$m)===1,'kernel-peer-credentials-unavailable');return ['pid'=>(int)$m[1],'uid'=>(int)$m[2],'gid'=>(int)$m[3]];
}

class ReachOwnerBroker {
 public array $scopes=[],$prepared=[],$jobs=[],$clients=[],$tasks=[];
 private string $instance;private ?string $epoch=null;private array $oldEpochs=[];private $clock;private array $core;private bool $fixture;private $claimVerifier;private bool $workflowFixture;private array $endTasks=[],$endTried=[],$fixtureEnds=[];
 public function __construct(?callable $clock=null,?array $core=null,?callable $claimVerifier=null,bool $workflowFixture=false){mb_need($core!==null||($claimVerifier===null&&!$workflowFixture),'fixture-injection-private-only');$this->clock=$clock??static fn()=>microtime(true);$this->core=$core??['/usr/bin/php',MB_CORE.'/runtime/nexus_owner.php'];$this->fixture=$core!==null;$this->instance=bin2hex(random_bytes(16));$this->claimVerifier=$claimVerifier;$this->workflowFixture=$workflowFixture;if(!$this->fixture){mb_core_verify();require_once MB_CORE.'/runtime/nexus_common.php';require_once MB_CORE.'/runtime/workflow_guard.php';wg_init();}}
 private function verified(array $binding):array{if($this->fixture)return $this->claimVerifier!==null?($this->claimVerifier)($binding):['binding'=>$binding,'anchor'=>[],'runtime_sha256'=>str_repeat('0',64)];return wg_verify($binding);}
 private function workflowVerified():bool{return $this->fixture?$this->workflowFixture:wg_workflow_verified();}
 private function queueEnd(string $sid,string $gen,string $reference):void{if(!$this->fixture){wg_end_generation($sid,$gen,$reference);return;}$id=hash('sha256',$sid.'|'.$gen);$this->fixtureEnds[$id]=['session_id'=>$sid,'generation'=>$gen,'reference'=>$reference,'path'=>$id];}
 private function reduceEnds():void{
  $pending=$this->fixture?array_values($this->fixtureEnds):wg_pending_ends();foreach($pending as$r){if(count($this->endTasks)>=8)break;$id=hash('sha256',$r['session_id'].'|'.$r['generation']);if(isset($this->endTasks[$id])||($this->endTried[$id]??0)>$this->now()-1)continue;$this->endTasks[$id]=true;$this->endTried[$id]=$this->now();
   try{$this->core(['command'=>'end','session_id'=>$r['session_id'],'generation'=>$r['generation'],'reference'=>$r['reference']],function($reply,$error)use($id,$r){unset($this->endTasks[$id]);if($error!==null)return;try{if($this->fixture){mb_need(($reply['session']['active']??true)===false&&($reply['session']['generation']??null)===$r['generation'],'fixture-end-ack');unset($this->fixtureEnds[$id]);}else wg_ack_end($r,$reply);foreach(array_keys($this->scopes)as$key){$v=&$this->scopes[$key];if($v['session_id']===$r['session_id']&&$v['generation']===$r['generation']){$v['generation_ended']=true;if($v['rotation_pending']&&!$v['ended']){$v['generation']=null;$v['rotation_pending']=false;$v['session_id']='mcp-'.$this->instance.'-'.$key.'-r'.$v['revision'];if($v['waiters'])$this->startScope($key);}}unset($v);}}catch(Throwable $ignored){};});}catch(Throwable $ignored){unset($this->endTasks[$id]);}
  }
 }
 public function now():float{return ($this->clock)();}
 public function live(string $key):bool{return isset($this->scopes[$key])&&!$this->scopes[$key]['ended']&&$this->scopes[$key]['expires_at']>$this->now()&&$this->scopes[$key]['binding']['gateway_epoch']===$this->epoch;}
 private function respond(int $client,array $v):void{if(!isset($this->clients[$client]))return;$this->clients[$client]['out']=mb_bytes($v)."\n";$this->clients[$client]['deadline']=$this->now()+5;}
 private function fail(int $client,string $why='private-owner-request-refused'):void{$this->respond($client,['ok'=>false,'reason'=>$why,'automatic_retry'=>false]);}
 private function core(array $input,callable $callback,int $timeout=35):void{
  if(!$this->fixture)mb_core_verify();
  $p=proc_open($this->core,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,'/',['PATH'=>'/usr/sbin:/usr/bin:/sbin:/bin','LANG'=>'C.UTF-8','LC_ALL'=>'C.UTF-8'],['bypass_shell'=>true]);mb_need(is_resource($p),'broker-core-start');foreach($pipes as$f)stream_set_blocking($f,false);
  $this->tasks[(int)$p]=['p'=>$p,'pipes'=>$pipes,'in'=>mb_bytes($input),'out'=>'','err'=>'','deadline'=>$this->now()+$timeout,'callback'=>$callback];
 }
 private function coreReply(array $task,int $exit):array{
  mb_need($exit===0&&$task['err']==='','broker-core-refused');$v=mb_json(trim($task['out']));mb_need(($v['ok']??true)!==false,'broker-core-refused');return $v;
 }
 public function driveTasks():void{
  foreach(array_keys($this->tasks)as$id){if(!isset($this->tasks[$id]))continue;$t=&$this->tasks[$id];$done=false;$exit=-1;$error=null;
   try{
    if(isset($t['pipes'][0])){if($t['in']!==''){$n=fwrite($t['pipes'][0],substr($t['in'],0,16384));mb_need($n!==false,'broker-core-input');$t['in']=substr($t['in'],$n);}if($t['in']===''){fclose($t['pipes'][0]);unset($t['pipes'][0]);}}
    $t['out'].=stream_get_contents($t['pipes'][1]);$t['err'].=stream_get_contents($t['pipes'][2]);mb_need(strlen($t['out'])<=MB_WIRE&&strlen($t['err'])<=8192,'broker-core-output');
    $s=proc_get_status($t['p']);if(!$s['running']){$done=true;$exit=$s['exitcode'];$t['out'].=stream_get_contents($t['pipes'][1]);$t['err'].=stream_get_contents($t['pipes'][2]);mb_need($t['in']==='','broker-core-input');}
    else mb_need($this->now()<$t['deadline'],'broker-core-timeout');
   }catch(Throwable $e){$done=true;$error=$e;proc_terminate($t['p'],9);}
   if(!$done){unset($t);continue;}
   $finished=$t;unset($t,$this->tasks[$id]);foreach($finished['pipes']as$f)fclose($f);$closed=proc_close($finished['p']);if($exit<0)$exit=$closed;
   try{$value=$error===null?$this->coreReply($finished,$exit):null;}catch(Throwable $e){$value=null;$error=$e;}
   try{($finished['callback'])($value,$error);}catch(Throwable $ignored){}
  }
 }
 private function control(string $key,array $input,callable $callback):void{
  $this->scopes[$key]['control_queue'][]=[$input,$callback];$this->nextControl($key);
 }
 private function nextControl(string $key):void{
  if($this->scopes[$key]['control_busy']||!$this->scopes[$key]['control_queue'])return;
  [$input,$callback]=array_shift($this->scopes[$key]['control_queue']);$this->scopes[$key]['control_busy']=true;
  try{$this->core($input,function($value,$error)use($key,$callback){
   try{$callback($value,$error);}finally{$this->scopes[$key]['control_busy']=false;$this->nextControl($key);}
  });}catch(Throwable $e){$this->scopes[$key]['control_busy']=false;try{$callback(null,$e);}finally{$this->nextControl($key);}}
 }
 private function finishScope(string $key,string $reference):void{
  if(!isset($this->scopes[$key]))return;$v=&$this->scopes[$key];if(!$v['ended']){$v['ended']=true;$v['mode']='ask_each';$v['revision']++;}
  foreach($this->prepared as$id=>$p)if($p['scope']===$key)unset($this->prepared[$id]);
  if(!$this->fixture)wg_end_scope($v['binding'],$reference);
  if($v['generation']!==null&&!$v['generation_ended'])$this->queueEnd($v['session_id'],$v['generation'],$reference);
 }
 private function selectEpoch(string $epoch):void{
  if($this->epoch===$epoch)return;mb_need(!isset($this->oldEpochs[$epoch]),'retired-gateway-epoch');
  if($this->epoch!==null){$this->oldEpochs[$this->epoch]=true;foreach(array_keys($this->scopes)as$key)$this->finishScope($key,'Gateway epoch changed');}$this->epoch=$epoch;
 }
 public function sweep():void{foreach(array_keys($this->scopes)as$key)if(!$this->scopes[$key]['ended']&&$this->scopes[$key]['expires_at']<=$this->now()){try{$fresh=$this->verified($this->scopes[$key]['binding']);mb_need($fresh['binding']['expires_at']>$this->now()&&$fresh['anchor']===$this->scopes[$key]['anchor'],'workflow-expired');$this->scopes[$key]['binding']=$fresh['binding'];$this->scopes[$key]['expires_at']=$fresh['binding']['expires_at'];}catch(Throwable $ignored){$this->finishScope($key,'Reach workflow expired');}}$this->reduceEnds();}
 private function startScope(string $key):void{
  $v=&$this->scopes[$key];if($v['starting']||$v['rotation_pending']||$v['ended'])return;$v['starting']=true;$sid=$v['session_id'];if(!$this->fixture)wg_start_intent($sid,$v['binding'],$v['revision']);
  $onStart=function($reply,$error)use($key,$sid){$waiting=$this->scopes[$key]['waiters'];$this->scopes[$key]['waiters']=[];$this->scopes[$key]['starting']=false;
   try{mb_need($error===null&&is_array($reply['session']??null),'owner-session-start-refused');$gen=mb_hex($reply['session']['generation']);$this->scopes[$key]['generation']=$gen;$this->scopes[$key]['generation_ended']=false;$verified=$this->verified($this->scopes[$key]['binding']);$this->scopes[$key]['binding']=$verified['binding'];$this->scopes[$key]['expires_at']=$verified['binding']['expires_at'];$this->scopes[$key]['anchor']=$verified['anchor'];if(!$this->fixture)wg_register($sid,$gen,$verified,$this->scopes[$key]['revision']);
    if(!$this->live($key)){$this->finishScope($key,'Workflow ended during initialization');throw new RuntimeException('ended-owner-workflow');}foreach($waiting as[$client,$callback]){try{$callback($key);}catch(Throwable $ignored){$this->fail($client);}}
   }catch(Throwable $ignored){$this->scopes[$key]['ended']=true;if(!$this->fixture)wg_cancel_start($sid);foreach($waiting as[$client,$callback])$this->fail($client,'owner-session-start-refused');}
  };try{$this->core(['command'=>'start','session_id'=>$sid,'reference'=>'Reach authenticated workflow '.$key],$onStart);}catch(Throwable $e){$onStart(null,$e);}
 }
 private function withScope(array $binding,int $client,callable $callback):void{
  $verified=$this->verified($binding);$binding=$verified['binding'];$key=mb_scope($binding);
  if(isset($this->scopes[$key])){mb_need($this->live($key),'ended-owner-workflow');$this->scopes[$key]['binding']=$binding;$this->scopes[$key]['expires_at']=(float)$binding['expires_at'];mb_need($this->scopes[$key]['anchor']===$verified['anchor'],'owner-authority-changed');if($this->scopes[$key]['generation']===null||$this->scopes[$key]['rotation_pending']){$this->scopes[$key]['waiters'][]=[$client,$callback];$this->startScope($key);return;}$callback($key);return;}
  $sid='mcp-'.$this->instance.'-'.$key.'-r0';$this->scopes[$key]=['binding'=>$binding,'anchor'=>$verified['anchor'],'expires_at'=>(float)$binding['expires_at'],'session_id'=>$sid,'generation'=>null,'mode'=>'ask_each','workflow_release_verified'=>$this->workflowVerified(),'revision'=>0,'ended'=>false,'generation_ended'=>false,'rotation_pending'=>false,'starting'=>false,'control_queue'=>[],'control_busy'=>false,'waiters'=>[[$client,$callback]]];$this->startScope($key);
 }
 private function base(string $key):array{return ['session_id'=>$this->scopes[$key]['session_id'],'generation'=>$this->scopes[$key]['generation']];}
 private function terminal(string $job):void{
  if($this->fixture)return;$v=$this->jobs[$job];if(isset($v['result'])){$v['receipt_sha256']=hash('sha256',mb_bytes($v['result']));unset($v['result']);}
  mb_new(MB_ROOT.'/state/results/'.$job.'.json',mb_bytes($v));unset($this->jobs[$job]);
 }
 private function job(string $job):array{
  if(isset($this->jobs[$job]))return $this->jobs[$job];mb_need(!$this->fixture,'owner-job-not-found');$v=mb_json(mb_read(MB_ROOT.'/state/results/'.$job.'.json'));
  if(isset($v['receipt_sha256'])){$raw=mb_read(MB_CORE.'/state/results/'.mb_hex($v['operation_id']).'.json');mb_need(hash('sha256',$raw)===mb_hex($v['receipt_sha256'],64),'owner-job-receipt-changed');$v['result']=mb_json($raw);}return $v;
 }
 private function prepare(array $v,int $client):void{
  $binding=$v['binding'];$this->withScope($binding,$client,function($key)use($v,$client){
   mb_need($this->live($key),'ended-owner-workflow');$revision=$this->scopes[$key]['revision'];
   $this->core(['command'=>'prepare',...$this->base($key),'vm_id'=>$v['binding']['vm_id'],'script_base64'=>$v['script_base64'],'arguments'=>$v['arguments'],'timeout_seconds'=>$v['timeout_seconds']],function($reply,$error)use($key,$revision,$client){
    if($error!==null||!$this->live($key)||$this->scopes[$key]['revision']!==$revision){$this->fail($client,'owner-prepare-refused');return;}
    try{$this->scopes[$key]['workflow_release_verified']=$this->workflowVerified();$request=$reply['request'];$id=mb_hex($request['operation_id']);$hash=mb_hex($reply['request_sha256'],64);$nonce=bin2hex(random_bytes(16));
     $this->prepared[$id]=['scope'=>$key,'hash'=>$hash,'nonce_hash'=>hash('sha256',$nonce),'revision'=>$revision,'used'=>false,'timeout'=>$request['timeout_seconds']];
     $this->respond($client,['ok'=>true,'operation_id'=>$id,'request_sha256'=>$hash,'approval_nonce'=>$nonce,'permission_mode'=>$this->scopes[$key]['mode']==='workflow'?'workflow':'ask_each','workflow_release_verified'=>$this->scopes[$key]['workflow_release_verified']]);
    }catch(Throwable $e){$this->fail($client,'owner-prepare-refused');}
   });
  });
 }
 private function launch(string $key,string $job,string $operation,string $hash):void{
  if(!$this->live($key)||$this->jobs[$job]['revision']!==$this->scopes[$key]['revision']){$this->jobs[$job]['state']='failed';$this->jobs[$job]['reason']='workflow-ended-before-dispatch';$this->terminal($job);return;}
  try{$fresh=$this->verified($this->scopes[$key]['binding']);mb_need($fresh['anchor']===$this->scopes[$key]['anchor'],'owner-authority-changed');$this->scopes[$key]['binding']=$fresh['binding'];$this->scopes[$key]['expires_at']=$fresh['binding']['expires_at'];}catch(Throwable $e){$this->jobs[$job]['state']='failed';$this->jobs[$job]['reason']='live-claim-refused-before-dispatch';$this->terminal($job);return;}
  $this->jobs[$job]['state']='running';
  try{if(!$this->fixture)wg_capture_operation($this->scopes[$key]['session_id'],$this->scopes[$key]['generation'],$operation,$hash,$this->scopes[$key]['revision'],$this->jobs[$job]['workflow']);$this->core(['command'=>'execute',...$this->base($key),'operation_id'=>$operation,'request_sha256'=>$hash],function($result,$error)use($key,$job,$operation,$hash){
   if($error!==null){$this->jobs[$job]['state']='uncertain';$this->jobs[$job]['reason']='private-owner-dispatch-uncertain';$this->terminal($job);return;}
   try{mb_need(($result['operation_id']??null)===$operation&&($result['request_sha256']??null)===$hash&&($result['vm_id']??null)===$this->scopes[$key]['binding']['vm_id'],'broker-result-binding');
    mb_need(in_array($result['state']??null,['completed','failed','timed_out','uncertain'],true),'broker-result-state');$this->jobs[$job]['state']=$result['state'];$this->jobs[$job]['result']=$result;
   }catch(Throwable $e){$this->jobs[$job]['state']='uncertain';$this->jobs[$job]['reason']='private-owner-result-uncertain';}$this->terminal($job);
  },430);$this->jobs[$job]['dispatched']=true;
  }catch(Throwable $e){$this->jobs[$job]['state']='uncertain';$this->jobs[$job]['reason']='private-owner-start-uncertain';$this->terminal($job);}
 }
 private function execute(array $v,int $client):void{
  $key=mb_scope($v['binding']);mb_need($this->live($key),'ended-owner-workflow');$this->scopes[$key]['expires_at']=(float)$v['binding']['expires_at'];$id=mb_hex($v['operation_id']);$hash=mb_hex($v['request_sha256'],64);$nonce=mb_hex($v['approval_nonce']);$p=$this->prepared[$id]??null;
  mb_need(is_array($p)&&$p['scope']===$key&&$p['hash']===$hash&&hash_equals($p['nonce_hash'],hash('sha256',$nonce))&&!$p['used']&&$p['revision']===$this->scopes[$key]['revision'],'owner-approval-nonce-refused');
  unset($this->prepared[$id]);$choice=$v['choice'];mb_need($choice===null||in_array($choice,['once','workflow'],true),'owner-approval-choice');
  if($choice==='workflow'||$choice===null)mb_need($this->scopes[$key]['workflow_release_verified']===true,'workflow-release-fencing-not-verified');
  if($choice===null)mb_need($v['approval_reference']===null&&$this->scopes[$key]['mode']==='workflow','native-owner-elicitation-required');else mb_reference($v['approval_reference']);
  $job=bin2hex(random_bytes(16));$this->jobs[$job]=['scope'=>$key,'state'=>'running','revision'=>$this->scopes[$key]['revision'],'operation_id'=>$id,'dispatched'=>false,'workflow'=>$choice===null||$choice==='workflow'];$this->respond($client,['ok'=>true,'job_id'=>$job,'operation_id'=>$id,'state'=>'running','automatic_retry'=>false]);
  if($choice===null){$this->launch($key,$job,$id,$hash);return;}
  $approval=$choice==='workflow'?['command'=>'allow-session',...$this->base($key),'vm_scope'=>[$v['binding']['vm_id']],'approval_reference'=>$v['approval_reference']]:
   ['command'=>'approve-once',...$this->base($key),'operation_id'=>$id,'request_sha256'=>$hash,'approval_reference'=>$v['approval_reference']];
  $this->control($key,$approval,function($reply,$error)use($key,$job,$id,$hash,$choice){
   if($error!==null){$this->jobs[$job]['state']='failed';$this->jobs[$job]['reason']='owner-approval-refused';if($this->jobs[$job]['revision']===$this->scopes[$key]['revision'])$this->scopes[$key]['mode']='ask_each';$this->terminal($job);return;}
   if($choice==='workflow'&&$this->live($key)&&$this->jobs[$job]['revision']===$this->scopes[$key]['revision']){try{if(!$this->fixture)wg_allow($this->scopes[$key]['session_id'],$this->scopes[$key]['generation'],$this->scopes[$key]['revision']);$this->scopes[$key]['mode']='workflow';}catch(Throwable $e){$this->jobs[$job]['state']='failed';$this->jobs[$job]['reason']='workflow-owner-choice-refused';$this->terminal($job);return;}}$this->launch($key,$job,$id,$hash);
  });
 }
 private function revokeScope(string $key,string $reference):void{
  $this->scopes[$key]['mode']='ask_each';$this->scopes[$key]['revision']++;
  foreach($this->prepared as$id=>$p)if($p['scope']===$key)unset($this->prepared[$id]);
  if(!$this->fixture)wg_revoke_scope($this->scopes[$key]['binding'],$reference);
  if($this->scopes[$key]['generation']!==null&&!$this->scopes[$key]['generation_ended']){
   $this->scopes[$key]['rotation_pending']=true;
   $this->queueEnd($this->scopes[$key]['session_id'],$this->scopes[$key]['generation'],$reference);
  }
 }
 private function management(array $v,int $client):void{
  $command=$v['command'];
  mb_fields($v,$command==='sessions'?['version','command','subject']:['version','command','subject','scope','reference']);
  mb_need(is_string($v['subject'])&&preg_match('/^[1-9][0-9]{0,19}$/D',$v['subject'])===1,'broker-management-owner');
  if($command==='revoke-sessions'){
   mb_need($v['scope']==='all'||(is_string($v['scope'])&&preg_match('/^[a-f0-9]{64}$/D',$v['scope'])===1),'broker-management-scope');
   mb_reference($v['reference']);$reduced=0;$failed=false;
   // Invalidate all matching in-memory revisions before any barrier can fail.
   // This also fences delayed approval callbacks and pending scope starts.
   $keys=[];foreach($this->scopes as$key=>$s)if($s['binding']['subject']===$v['subject']&&($v['scope']==='all'||$v['scope']===$key))$keys[]=$key;
   foreach($keys as$key){$this->scopes[$key]['mode']='ask_each';$this->scopes[$key]['revision']++;}
   foreach($this->prepared as$id=>$p)if(in_array($p['scope'],$keys,true))unset($this->prepared[$id]);
   foreach($keys as$key){try{$this->revokeScope($key,$v['reference']);$reduced++;}catch(Throwable $ignored){$failed=true;}}
   mb_need(!$failed,'owner-revoke-incomplete');
   $this->respond($client,['ok'=>true,'state'=>'revoked','permission_mode'=>'ask_each','durable_reduction_accepted'=>true,'sessions_reduced'=>$reduced]);return;
  }
  $rows=[];
  foreach($this->scopes as$key=>$s){
   if($s['binding']['subject']!==$v['subject'])continue;
   $jobs=count(array_filter($this->jobs,static fn($j)=>$j['scope']===$key&&$j['state']==='running'));
   if(($s['ended']||$s['mode']!=='workflow')&&$jobs===0)continue;
   $verified=false;
   if(!$s['ended'])try{$fresh=$this->verified($s['binding']);$verified=$fresh['anchor']===$s['anchor']&&$fresh['binding']['expires_at']>$this->now();if($verified){$this->scopes[$key]['binding']=$fresh['binding'];$this->scopes[$key]['expires_at']=$fresh['binding']['expires_at'];$s=$this->scopes[$key];}}catch(Throwable $ignored){}
   $rows[]=['scope'=>$key,'session_id'=>$s['binding']['control_id'],'vm_id'=>$s['binding']['vm_id'],'permission_mode'=>$s['mode'],'expires_at'=>$s['expires_at'],'verified'=>$verified,'ended'=>$s['ended'],'jobs_in_progress'=>$jobs];
  }
  mb_need(count($rows)<=256,'owner-session-list-bound');
  $this->respond($client,['ok'=>true,'sessions'=>$rows]);
 }
 public function request(array $v,int $client,int $uid):void{
  try{
   mb_need(($v['version']??null)===1&&is_string($v['command']??null),'broker-version');$command=$v['command'];
   if($command==='ping'){mb_fields($v,['version','command']);mb_need(in_array($uid,[0,MB_PEER_UID],true),'broker-peer-uid');$this->respond($client,['ok'=>true,'service'=>'nexus-owner-mcp','protocol_version'=>1,'peer_uid'=>MB_PEER_UID,'active_jobs'=>count(array_filter($this->jobs,static fn($j)=>$j['state']==='running'))]);return;}
   mb_need($uid===MB_PEER_UID,'broker-peer-uid');
   if(in_array($command,['sessions','revoke-sessions'],true)){$this->management($v,$client);return;}
   $fields=[
    'prepare'=>['version','command','binding','script_base64','arguments','timeout_seconds'],
    'execute'=>['version','command','binding','operation_id','request_sha256','approval_nonce','choice','approval_reference'],
    'poll'=>['version','command','binding','job_id'],
    'revoke'=>['version','command','binding','reference'],'end'=>['version','command','binding','reference'],
    'renew'=>['version','command','binding']];mb_need(isset($fields[$command]),'broker-command');mb_fields($v,$fields[$command]);mb_need(is_array($v['binding']),'broker-binding');
   $v['binding']=mb_binding($v['binding'],$this->now(),!in_array($command,['revoke','end'],true));$key=mb_scope($v['binding']);
   if(!in_array($command,['revoke','end'],true)){$verified=$this->verified($v['binding']);$v['binding']=$verified['binding'];$this->selectEpoch($v['binding']['gateway_epoch']);}
   if($command==='prepare'){$this->prepare($v,$client);return;}
   if($command==='execute'){$this->execute($v,$client);return;}
   if($command==='poll'){$job=mb_hex($v['job_id']);mb_need($this->live($key),'owner-job-scope');$j=$this->job($job);mb_need($j['scope']===$key,'owner-job-scope');$this->scopes[$key]['expires_at']=(float)$v['binding']['expires_at'];$response=['ok'=>true,'job_id'=>$job,'operation_id'=>$j['operation_id'],'state'=>$j['state'],'automatic_retry'=>false];if(isset($j['result']))$response['result']=$j['result'];if(isset($j['reason']))$response['reason']=$j['reason'];$this->respond($client,$response);return;}
   if($command==='renew'){mb_need($this->live($key),'ended-owner-workflow');$this->scopes[$key]['expires_at']=(float)$v['binding']['expires_at'];$this->respond($client,['ok'=>true,'permission_mode'=>$this->scopes[$key]['mode'],'expires_at'=>$this->scopes[$key]['expires_at']]);return;}
   mb_reference($v['reference']);
   if(!isset($this->scopes[$key])){if(!$this->fixture){if($command==='end')wg_end_scope($v['binding'],$v['reference']);else wg_revoke_scope($v['binding'],$v['reference']);}$this->respond($client,['ok'=>true,'permission_mode'=>'ask_each','state'=>$command==='end'?'ended':'revoked','durable_reduction_accepted'=>true]);return;}
   if($command==='end'){$this->finishScope($key,$v['reference']);$this->respond($client,['ok'=>true,'state'=>'ended','permission_mode'=>'ask_each','durable_reduction_accepted'=>true]);return;}
   $this->revokeScope($key,$v['reference']);
   $this->respond($client,['ok'=>true,'state'=>'revoked','permission_mode'=>'ask_each','durable_reduction_accepted'=>true]);

  }catch(Throwable $e){$why=$e instanceof RuntimeException&&preg_match('/^[a-z0-9-]{1,80}$/D',$e->getMessage())?$e->getMessage():'private-owner-request-refused';$this->fail($client,$why);}
 }
 public function closeAll():void{foreach(array_keys($this->scopes)as$key)$this->finishScope($key,'Nexus owner broker stopped');}
}

function mb_run_directory():void{
 mb_path('/run',true);if(!file_exists(MB_RUN)&&!is_link(MB_RUN))mb_need(mkdir(MB_RUN,0750)&&chown(MB_RUN,0)&&chgrp(MB_RUN,MB_PEER_UID)&&chmod(MB_RUN,0750),'broker-run-directory');
 $s=lstat(MB_RUN);mb_need(!is_link(MB_RUN)&&($s['mode']&0170000)===0040000&&$s['uid']===0&&in_array($s['gid'],[0,MB_PEER_UID],true)&&($s['mode']&0022)===0,'broker-run-directory');
 $names=array_values(array_diff(scandir(MB_RUN),['.','..']));foreach($names as$n)mb_need(in_array($n,['.broker.lock','owner.sock','broker.pid','status.json','claim-fence.lock'],true),'unexpected-broker-run-file');
 mb_need(chgrp(MB_RUN,MB_PEER_UID)&&chmod(MB_RUN,0750),'broker-run-protect');
 $fence=MB_RUN.'/claim-fence.lock';if(!file_exists($fence)&&!is_link($fence)){$f=fopen($fence,'x+b');mb_need(is_resource($f)&&chown($fence,0)&&chgrp($fence,10008)&&chmod($fence,0640),'broker-claim-fence-create');fclose($f);}$s=lstat($fence);mb_need(!is_link($fence)&&($s['mode']&0170000)===0100000&&$s['uid']===0&&$s['gid']===10008&&($s['mode']&07777)===0640&&$s['nlink']===1,'broker-claim-fence-protect');
}
function mb_run_parent():void{mb_path('/run',true);$s=@lstat(MB_RUN);mb_need(is_array($s)&&!is_link(MB_RUN)&&($s['mode']&0170000)===0040000&&$s['uid']===0&&$s['gid']===MB_PEER_UID&&($s['mode']&07777)===0750,'protected-broker-run-parent');}
function mb_run_file(string $path):void{
 mb_need(dirname($path)===MB_RUN&&in_array(basename($path),['.broker.lock','broker.pid','status.json'],true),'fixed-broker-run-file');mb_run_parent();$s=@lstat($path);
 mb_need(is_array($s)&&!is_link($path)&&($s['mode']&0170000)===0100000&&$s['uid']===0&&$s['gid']===0&&($s['mode']&07777)===0600&&$s['nlink']===1,'protected-broker-run-file');
}
function mb_serve():void{
 mb_runtime_verify();mb_run_directory();$lockPath=MB_RUN.'/.broker.lock';if(!file_exists($lockPath)){ $f=fopen($lockPath,'x');mb_need(is_resource($f)&&chown($lockPath,0)&&chgrp($lockPath,0)&&chmod($lockPath,0600),'broker-lock-create');fclose($f);}mb_run_file($lockPath);$lock=fopen($lockPath,'r+b');mb_need(is_resource($lock)&&flock($lock,LOCK_EX|LOCK_NB),'broker-already-running');
 if(file_exists(MB_SOCKET)||is_link(MB_SOCKET)){$s=lstat(MB_SOCKET);mb_need(!is_link(MB_SOCKET)&&($s['mode']&0170000)===0140000&&$s['uid']===0&&$s['gid']===MB_PEER_UID,'stale-broker-socket');mb_need(unlink(MB_SOCKET),'stale-broker-socket-remove');}
 $server=stream_socket_server('unix://'.MB_SOCKET,$errno,$error,STREAM_SERVER_BIND|STREAM_SERVER_LISTEN);mb_need(is_resource($server)&&chown(MB_SOCKET,0)&&chgrp(MB_SOCKET,MB_PEER_UID)&&chmod(MB_SOCKET,0660),'broker-socket-start');stream_set_blocking($server,false);
 $pid=MB_RUN.'/broker.pid';if(file_exists($pid)||is_link($pid))mb_run_file($pid);$f=fopen($pid,'wb');mb_need(is_resource($f)&&chown($pid,0)&&chgrp($pid,0)&&chmod($pid,0600)&&fwrite($f,(string)posix_getpid())>0,'broker-pid');fclose($f);mb_run_file($pid);
 $broker=new ReachOwnerBroker();$stop=false;if(function_exists('pcntl_async_signals')){pcntl_async_signals(true);pcntl_signal(SIGTERM,static function()use(&$stop){$stop=true;});pcntl_signal(SIGINT,static function()use(&$stop){$stop=true;});}
 try{while(!$stop){
  // One bounded peer check per tick leaves existing revocations and children
  // runnable even if the local accept queue is continuously replenished.
  if(($conn=@stream_socket_accept($server,0))!==false){stream_set_blocking($conn,false);try{$cred=mb_peer_credentials($conn);}catch(Throwable $e){$cred=false;}$id=(int)$conn;if(!is_array($cred)||!in_array($cred['uid']??null,[0,MB_PEER_UID],true))fclose($conn);else$broker->clients[$id]=['stream'=>$conn,'uid'=>$cred['uid'],'in'=>'','out'=>null,'submitted'=>false,'deadline'=>$broker->now()+30];}
  foreach(array_keys($broker->clients)as$id){if(!isset($broker->clients[$id]))continue;$c=&$broker->clients[$id];
   if($c['out']!==null){$n=@fwrite($c['stream'],substr($c['out'],0,16384));if($n!==false)$c['out']=substr($c['out'],$n);if($n===false||$c['out']===''||$broker->now()>$c['deadline']){fclose($c['stream']);unset($c,$broker->clients[$id]);}else unset($c);continue;}
   if(!$c['submitted']){$chunk=@fread($c['stream'],16384);if($chunk===false){fclose($c['stream']);unset($c,$broker->clients[$id]);continue;}$c['in'].=$chunk;if(strlen($c['in'])>MB_WIRE){fclose($c['stream']);unset($c,$broker->clients[$id]);continue;}
    if(str_contains($c['in'],"\n")||feof($c['stream'])){$raw=trim($c['in']);$uid=$c['uid'];$c['submitted']=true;unset($c);try{$broker->request(mb_json($raw),$id,$uid);}catch(Throwable $e){$broker->clients[$id]['out']=mb_bytes(['ok'=>false,'reason'=>'broker-wire-refused','automatic_retry'=>false])."\n";}continue;}}
   if($broker->now()>$c['deadline']){fclose($c['stream']);unset($c,$broker->clients[$id]);}else unset($c);
  }
  $broker->sweep();$broker->driveTasks();usleep(10000);
 }}finally{$broker->closeAll();$broker->sweep();$end=microtime(true)+5;while($broker->tasks&&microtime(true)<$end){$broker->driveTasks();$broker->sweep();usleep(10000);}foreach($broker->clients as$c)fclose($c['stream']);fclose($server);if(file_exists(MB_SOCKET))unlink(MB_SOCKET);if(file_exists($pid))unlink($pid);flock($lock,LOCK_UN);fclose($lock);}
}
function mb_ping():array{
 mb_runtime_verify();mb_run_parent();$s=lstat(MB_SOCKET);mb_need(!is_link(MB_SOCKET)&&($s['mode']&0170000)===0140000&&$s['uid']===0&&$s['gid']===MB_PEER_UID&&($s['mode']&07777)===0660,'broker-health-socket');
 $socket=stream_socket_client('unix://'.MB_SOCKET,$errno,$error,1);mb_need(is_resource($socket),'broker-health-connect');stream_set_timeout($socket,2);
 try{mb_need(fwrite($socket,"{\"version\":1,\"command\":\"ping\"}\n")===31,'broker-health-write');stream_socket_shutdown($socket,STREAM_SHUT_WR);$line=fgets($socket,8193);mb_need(is_string($line)&&str_ends_with($line,"\n"),'broker-health-read');$v=mb_json(trim($line));mb_need(($v['ok']??null)===true&&($v['service']??null)==='nexus-owner-mcp'&&($v['peer_uid']??null)===MB_PEER_UID,'broker-health-response');return $v;}finally{fclose($socket);}
}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__){try{mb_need($argc===2&&in_array($argv[1],['check','serve','ping'],true)&&__FILE__===MB_ROOT.'/owner_broker.php','fixed-broker-command');if($argv[1]==='check'){mb_runtime_verify();echo '{"ok":true,"mode":"check","peer_uid":10008,"socket":"/run/reach-owner-mcp/owner.sock","writes":false}' ."\n";}elseif($argv[1]==='ping')echo mb_bytes(mb_ping())."\n";else mb_serve();}catch(Throwable $e){$why=$e instanceof RuntimeException&&preg_match('/^[a-z0-9-]{1,80}$/D',$e->getMessage())?$e->getMessage():'nexus-owner-broker-refused';echo mb_bytes(['ok'=>false,'reason'=>$why,'automatic_retry'=>false])."\n";exit(1);}}
