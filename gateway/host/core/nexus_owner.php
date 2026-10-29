<?php
/* Private Nexus-root console only. Never expose this entry as a public MCP tool.
 * Human references are audit pointers checked by the trusted owner operator,
 * not cryptographic proof of chat consent. All transport/key/state is Nexus-local. */
declare(strict_types=1);
ini_set('display_errors','0');ini_set('log_errors','0');umask(0077);
require __DIR__.'/nexus_common.php';
function no_ledger_stderr(string $value):bool{
 return $value===''||$value==="WARNING: Your kernel does not support swap limit capabilities or the cgroup is not mounted. Memory limited without swap.\n";
}
function no_ledger(array $request):array{
 nx_path('/usr/bin/docker');$result=nx_run(['/usr/bin/docker','run','--rm','-i','--read-only','--network','none','--cap-drop','ALL',
  '--security-opt','no-new-privileges','--pids-limit','64','--memory','128m','--cpus','1','--tmpfs','/tmp:rw,noexec,nosuid,size=16m',
  '-v',NX_ROOT.'/runtime:/code:ro','-v',NX_ROOT.'/state/ledger:/state:rw',NX_IMAGE,'python','-I','-S','-B','/code/ledger_command.py'],nx_bytes($request),30,65536);
 $value=nx_json(trim($result['out']),65536);nx_need($result['exit']===0&&no_ledger_stderr($result['err'])&&($value['ok']??null)===true,'owner-ledger-refused');return $value['result']??[];
}
function no_process_stamp(int $pid):array{
 nx_need($pid>1,'owner-console-required');$path='/proc/'.$pid;$info=@lstat($path);nx_need(is_array($info)&&$info['uid']===0,'root-owner-console-required');
 $raw=@file_get_contents($path.'/stat');nx_need(is_string($raw)&&strlen($raw)<=8192&&strrpos($raw,')')!==false,'owner-console-unavailable');$fields=preg_split('/\s+/',trim(substr($raw,strrpos($raw,')')+1)));
 nx_need(count($fields)>19&&ctype_digit($fields[19])&&$fields[0]!=='Z','owner-console-ended');return ['pid'=>$pid,'created'=>$fields[19]];
}
function no_console():array{return no_process_stamp(posix_getppid());}
function no_binding_path(string $sid):string{return NX_ROOT.'/state/sessions/'.hash('sha256',$sid).'.json';}
function no_active(string $sid,string $generation,array $console):array{
 $b=nx_json(nx_read(no_binding_path($sid),8192));nx_need(($b['session_id']??null)===$sid&&($b['generation']??null)===$generation&&($b['console']??null)===$console,'owner-console-session-mismatch');
 nx_need(no_process_stamp($console['pid'])===$console&&!file_exists(NX_ROOT.'/state/sessions/'.$generation.'.ended'),'owner-console-session-ended');
 $state=no_ledger(['command'=>'status','session_id'=>$sid,'generation'=>$generation]);nx_need(($state['active']??null)===true,'owner-session-ended');return $state;
}
function no_request(array $input):array{
 $id=nx_hex($input['operation_id']??null,32);$expected=nx_hex($input['request_sha256']??null);$raw=nx_read(NX_ROOT.'/state/requests/'.$id.'.json');$request=nx_packet(nx_json($raw));nx_need(nx_bytes($request)===$raw&&hash('sha256',$raw)===$expected,'captured-request-changed');return [$request,$raw,$expected];
}
function no_finish(array $capture,string $state):array{[$sid,$generation,$request,$sha]=$capture;return no_ledger(['command'=>'finish','session_id'=>$sid,'generation'=>$generation,'operation_id'=>$request['operation_id'],'request_sha256'=>$sha,'state'=>$state]);}
function no_main(array $argv,array $input):array{
 nx_need(count($argv)===1&&__FILE__===NX_ROOT.'/runtime/nexus_owner.php','fixed-private-owner-cli');nx_runtime();require_once __DIR__.'/workflow_guard.php';$console=no_console();$command=$input['command']??null;
 $fields=[
  'start'=>['command','session_id','reference'],
  'status'=>['command','session_id','generation'],
  'prepare'=>['command','session_id','generation','vm_id','script_base64','arguments','timeout_seconds'],
  'approve-once'=>['command','session_id','generation','operation_id','request_sha256','approval_reference'],
  'allow-session'=>['command','session_id','generation','vm_scope','approval_reference'],
  'revoke'=>['command','session_id','generation','reference'],
  'end'=>['command','session_id','generation','reference'],
  'execute'=>['command','session_id','generation','operation_id','request_sha256']];
 nx_need(is_string($command)&&isset($fields[$command]),'private-owner-command');nx_fields($input,$fields[$command]);$sid=nx_id($input['session_id']);
 nx_path(NX_ROOT.'/state',true,0700);$lockPath=NX_ROOT.'/state/.controller.lock';if(!file_exists($lockPath))nx_new($lockPath,'');nx_path($lockPath,false,0600);$lock=fopen($lockPath,'r+b');nx_need(is_resource($lock)&&flock($lock,LOCK_EX),'owner-controller-lock');
 $child=null;$capture=null;
 try{
  if($command==='start'){
   $state=no_ledger(['command'=>'start','session_id'=>$sid,'reference'=>nx_reference($input['reference'])]);
   nx_atomic(no_binding_path($sid),['version'=>1,'session_id'=>$sid,'generation'=>$state['generation'],'console'=>$console]);
   return ['ok'=>true,'session'=>$state,'owner_console'=>$console,'permission_lifetime'=>'this Nexus owner console and explicit session generation','physical_workstation_required'=>false];
  }
  $generation=nx_hex($input['generation'],32);
  // Any authenticated Nexus-root console may reduce another console's grant.
  // Starting, approving and executing still require this exact live console.
  if(in_array($command,['revoke','end'],true)){
   $b=nx_json(nx_read(no_binding_path($sid),8192));nx_need(($b['session_id']??null)===$sid&&($b['generation']??null)===$generation,'owner-session-mismatch');
   $reference=nx_reference($input['reference']);
   if($command==='end'){$ended=NX_ROOT.'/state/sessions/'.$generation.'.ended';if(!file_exists($ended))nx_new($ended,nx_bytes(['reference'=>$reference,'ended_at'=>time()]));}
   return ['ok'=>true,'session'=>no_ledger(['command'=>$command,'session_id'=>$sid,'generation'=>$generation,'reference'=>$reference])];
  }
  $state=no_active($sid,$generation,$console);
  if($command==='status')return ['ok'=>true,'session'=>$state,'owner_console'=>$console,'physical_workstation_required'=>false];
  if($command==='prepare'){
   $script=base64_decode(is_string($input['script_base64'])?$input['script_base64']:'!',true);nx_need(is_string($script),'owner-script-encoding');
   $packet=nx_packet(['version'=>2,'operation'=>'execute-owner-vm','vm_id'=>$input['vm_id'],'operation_id'=>bin2hex(random_bytes(16)),
    'script_base64'=>$input['script_base64'],'script_sha256'=>hash('sha256',$script),'arguments'=>$input['arguments'],'timeout_seconds'=>$input['timeout_seconds']]);
   $raw=nx_bytes($packet);nx_new(NX_ROOT.'/state/requests/'.$packet['operation_id'].'.json',$raw);
   return ['ok'=>true,'request'=>$packet,'request_sha256'=>hash('sha256',$raw),'script_utf8'=>$script,'administrator_permission_granted'=>false];
  }
  if($command==='allow-session'){
   $scope=$input['vm_scope'];nx_need(is_array($scope)&&array_is_list($scope)&&count($scope)>0&&count($scope)<=2,'owner-vm-scope');foreach($scope as$vm)nx_need(is_string($vm)&&isset(NX_TARGETS[$vm]),'owner-vm-scope');
   return ['ok'=>true,'session'=>no_ledger(['command'=>'allow-session','session_id'=>$sid,'generation'=>$generation,'vm_scope'=>$scope,'approval_reference'=>nx_reference($input['approval_reference'])])];
  }
  [$request,$raw,$sha]=no_request($input);$base=['session_id'=>$sid,'generation'=>$generation,'operation_id'=>$request['operation_id'],'request_sha256'=>$sha,'vm_id'=>$request['vm_id']];
  if($command==='approve-once')return ['ok'=>true,'approval'=>no_ledger(['command'=>'approve-once',...$base,'approval_reference'=>nx_reference($input['approval_reference'])])];
  no_ledger(['command'=>'consume',...$base]);$capture=[$sid,$generation,$request,$sha];
  // The global owner lock fences revoke/end/start through this final assertion
  // and nonblocking child start. The durable one-use consumption precedes start.
  no_active($sid,$generation,$console);no_ledger(['command'=>'assert',...$base]);
  $child=wg_dispatch($sid,$generation,$request['operation_id'],$sha,$console,static fn()=>nx_spawn(['/usr/bin/php',NX_ROOT.'/runtime/nexus_transport.php','--request-sha256',$sha]));
 }catch(Throwable $e){if($capture!==null){try{no_finish($capture,'uncertain');}catch(Throwable $ignored){}}throw $e;
 }finally{flock($lock,LOCK_UN);fclose($lock);}
 nx_need($child!==null&&$capture!==null,'owner-dispatch-state');
 try{
  $reply=nx_collect($child,$raw,$request['timeout_seconds']+120);nx_need($reply['exit']===0&&$reply['err']==='','owner-transport-uncertain');$result=nx_json(trim($reply['out']));
  nx_need(($result['operation_id']??null)===$request['operation_id']&&($result['request_sha256']??null)===$sha&&($result['vm_id']??null)===$request['vm_id'],'owner-result-binding');
  $terminal=($result['state']??null)==='uncertain'?'uncertain':((($result['state']??null)==='completed')?'completed':'failed');
  $lock=fopen($lockPath,'r+b');nx_need(is_resource($lock)&&flock($lock,LOCK_EX),'owner-controller-lock');try{no_finish($capture,$terminal);nx_new(NX_ROOT.'/state/results/'.$request['operation_id'].'.json',nx_bytes($result));}finally{flock($lock,LOCK_UN);fclose($lock);}return $result;
 }catch(Throwable $e){
  $lock=fopen($lockPath,'r+b');if(is_resource($lock)){if(flock($lock,LOCK_EX)){try{no_finish($capture,'uncertain');}catch(Throwable $ignored){}flock($lock,LOCK_UN);}fclose($lock);}throw $e;
 }
}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__){try{$raw=stream_get_contents(STDIN,262145);nx_need(is_string($raw),'owner-input');echo nx_bytes(no_main($argv,nx_json($raw)))."\n";}catch(Throwable $e){$why=$e instanceof RuntimeException&&preg_match('/^[a-z0-9-]{1,80}$/D',$e->getMessage())?$e->getMessage():'private-nexus-owner-refused';echo nx_bytes(['ok'=>false,'reason'=>$why,'automatic_retry'=>false,'inspect_before_new_attempt'=>true])."\n";exit(1);}}
