<?php
declare(strict_types=1);
ini_set('display_errors','0');ini_set('log_errors','0');umask(0077);
require __DIR__.'/nexus_common.php';
const NT_SSH_PQ_NOTICE="** WARNING: connection is not using a post-quantum key exchange algorithm.\n** This session may be vulnerable to \"store now, decrypt later\" attacks.\n** The server may need to be upgraded. See https://openssh.com/pq.html\n";
function nt_stderr_allowed(string $vm,string $stderr):bool{
 if($stderr==='')return true;if($vm!=='vm-alpha')return false;
 return $stderr===NT_SSH_PQ_NOTICE||$stderr===str_replace("\n","\r\n",NT_SSH_PQ_NOTICE);
}
function nt_transport_notices(string $vm,string $stderr):array{
 nx_need(nt_stderr_allowed($vm,$stderr),'owner-transport-refused');return $stderr===''?[]:[['code'=>'ssh-post-quantum-kex-warning','message'=>$stderr]];
}
function nt_main(array $argv,string $raw):array{
 nx_need(count($argv)===3&&$argv[1]==='--request-sha256'&&__FILE__===NX_ROOT.'/runtime/nexus_transport.php','fixed-nexus-transport');$expected=nx_hex($argv[2]);$config=nx_runtime();$request=nx_packet(nx_json($raw));nx_need(nx_bytes($request)===$raw&&hash('sha256',$raw)===$expected,'captured-owner-request');
 if($request['vm_id']==='vm-beta'){
  nx_need(hash('sha256',nx_read(NX_GATE))===$config['owner_gate_sha256'],'existing-owner-gate-changed');$reply=nx_run(['/usr/bin/php',NX_GATE],$raw,$request['timeout_seconds']+90);
 }elseif($request['vm_id']==='vm-gamma'){
  $reply=nx_run(['/usr/bin/php',NX_ROOT.'/runtime/nexus_vm2.php','--request-sha256',$expected],$raw,$request['timeout_seconds']+90);
 }elseif($request['vm_id']==='vm-alpha'){
  foreach(['vm-alpha','vm-alpha.known_hosts']as$name)nx_path(NX_ROOT.'/ssh/'.$name,false,0600);nx_path('/usr/bin/ssh');
  $reply=nx_run(['/usr/bin/ssh','-F','/dev/null','-T','-a','-x','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
   '-o','StrictHostKeyChecking=yes','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','ConnectTimeout=10',
   '-o','ServerAliveInterval=5','-o','ServerAliveCountMax=3','-o','BindAddress=203.0.113.1',
   '-o','UserKnownHostsFile='.NX_ROOT.'/ssh/vm-alpha.known_hosts','-o','GlobalKnownHostsFile=/dev/null',
   '-i',NX_ROOT.'/ssh/vm-alpha','ReachOwner@203.0.113.2','nexus-reach-owner-v1'],$raw,$request['timeout_seconds']+90);
 }else{throw new RuntimeException('owner-vm-target');}
 nx_need($reply['exit']===0&&nt_stderr_allowed($request['vm_id'],$reply['err']),'owner-transport-refused');$v=nx_json(trim($reply['out']));
 foreach(['version'=>2,'operation'=>'execute-owner-vm','vm_id'=>$request['vm_id'],'operation_id'=>$request['operation_id'],
  'request_sha256'=>$expected,'script_sha256'=>$request['script_sha256'],'automatic_retry'=>false]as$k=>$value)nx_need(array_key_exists($k,$v)&&$v[$k]===$value,'owner-receipt-binding');
 nx_need(in_array($v['state']??null,['completed','failed','timed_out','uncertain'],true)&&is_string($v['output']??null)&&strlen($v['output'])<=65536,'owner-receipt-shape');
 if($v['state']!=='uncertain'){$target=NX_TARGETS[$request['vm_id']];nx_need(($v['administrator']??null)===true&&($v['account_sid']??null)===$target['sid']&&($v['machine_uuid']??null)===$target['uuid']&&($v['process_tree_cleanup_confirmed']??null)===true,'owner-receipt-identity');}
 nx_need($v['state']!=='completed'||($v['exit_code']??null)===0,'owner-receipt-status');$notices=nt_transport_notices($request['vm_id'],$reply['err']);if($notices)$v['transport_notices']=$notices;return $v;
}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__){try{$raw=stream_get_contents(STDIN,262145);nx_need(is_string($raw),'owner-input');echo nx_bytes(nt_main($argv,$raw))."\n";}catch(Throwable $e){echo '{"ok":false,"reason":"nexus-owner-transport-refused","automatic_retry":false}' ."\n";exit(1);}}
