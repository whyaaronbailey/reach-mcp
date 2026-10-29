<?php
declare(strict_types=1);
const NX_ROOT='/var/lib/reach-owner/core';
const NX_GATE='/var/lib/reach-owner/guest-adapter/owner-entry.php';
const NX_IMAGE='python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c';
const NX_RUNTIME=['nexus_common.php','nexus_owner.php','nexus_transport.php','ledger_command.py','owner_session_permissions.py','workflow_guard.php','workflow_claim.py','nexus_vm2.php'];
const NX_TARGETS=['vm-alpha'=>['uuid'=>'2ab91530-757f-5639-b81a-335686c33b2e','sid'=>'S-1-5-21-100-200-300-1000'],
 'vm-beta'=>['uuid'=>'e926e18d-0c2a-5aaa-b451-1c49f0da5744','sid'=>'S-1-5-18'],
 'vm-gamma'=>['uuid'=>'435cefb1-5990-5dfa-9f0c-06ddd5cee23b','sid'=>'S-1-5-18']];
function nx_need(bool $v,string $why):void{if(!$v)throw new RuntimeException($why);}
function nx_path(string $path,bool $directory=false,?int $exact=null):void{
 for($at=$path;;$at=dirname($at)){$s=@lstat($at);nx_need(is_array($s)&&!is_link($at)&&($s['mode']&0170000)===($at===$path&&!$directory?0100000:0040000)
  &&$s['uid']===0&&$s['gid']===0&&($s['mode']&0022)===0,'protected-nexus-owner-path');
  if($at===$path){if(!$directory)nx_need($s['nlink']===1,'protected-nexus-owner-file');if($exact!==null)nx_need(($s['mode']&07777)===$exact,'protected-nexus-owner-mode');}if($at==='/')break;}
}
function nx_read(string $path,int $maximum=262144):string{
 nx_path($path);$s=lstat($path);nx_need($s['size']<=$maximum,'owner-file-bound');$f=fopen($path,'rb');nx_need(is_resource($f),'owner-file-open');
 try{$opened=fstat($f);foreach(['dev','ino','mode','uid','gid','size','mtime','ctime','nlink']as$k)nx_need($opened[$k]===$s[$k],'owner-file-changed');$raw=stream_get_contents($f,$maximum+1);nx_need(is_string($raw)&&strlen($raw)===$s['size'],'owner-file-read');}finally{fclose($f);}
 clearstatcache(true,$path);$after=lstat($path);foreach(['dev','ino','mode','uid','gid','size','mtime','ctime','nlink']as$k)nx_need($after[$k]===$s[$k],'owner-file-changed');return $raw;
}
function nx_json(string $raw,int $max=262144):array{nx_need(strlen($raw)<=$max,'owner-json-bound');$v=json_decode($raw,true,32,JSON_THROW_ON_ERROR);nx_need(is_array($v),'owner-json-object');return $v;}
function nx_bytes(array $v):string{return json_encode($v,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);}
function nx_fields(array $v,array $keys):void{$a=array_keys($v);sort($a);sort($keys);nx_need($a===$keys,'owner-request-fields');}
function nx_id(mixed $v,string $why='invalid-session-id'):string{nx_need(is_string($v)&&(bool)preg_match('/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/D',$v),$why);return $v;}
function nx_hex(mixed $v,int $length=64):string{nx_need(is_string($v)&&(bool)preg_match('/^[a-f0-9]{'.$length.'}$/D',$v),'invalid-owner-hash');return $v;}
function nx_reference(mixed $v):string{nx_need(is_string($v)&&strlen($v)>0&&strlen($v)<=1024&&!preg_match('/[\x00-\x1f\x7f]/',$v),'invalid-approval-reference');return $v;}
function nx_new(string $path,string $raw):void{
 nx_path(dirname($path),true,0700);nx_need(!file_exists($path)&&!is_link($path),'owner-file-already-exists');$f=fopen($path,'x+b');nx_need(is_resource($f),'owner-file-create');
 try{nx_need(chown($path,0)&&chgrp($path,0)&&chmod($path,0600)&&fwrite($f,$raw)===strlen($raw)&&fflush($f),'owner-file-write');if(function_exists('fsync'))nx_need(fsync($f),'owner-file-sync');}finally{fclose($f);}nx_need(nx_read($path,max(1,strlen($raw)))===$raw,'owner-file-verification');
}
function nx_atomic(string $path,array $value):void{nx_path(dirname($path),true,0700);if(file_exists($path)||is_link($path))nx_path($path,false,0600);$tmp=dirname($path).'/.update-'.bin2hex(random_bytes(12));nx_new($tmp,nx_bytes($value));nx_need(rename($tmp,$path),'owner-atomic-write');}
function nx_dir(string $path):void{nx_path(dirname($path),true);if(!file_exists($path)&&!is_link($path))nx_need(mkdir($path,0700)&&chown($path,0)&&chgrp($path,0)&&chmod($path,0700),'owner-directory-create');nx_path($path,true,0700);}
function nx_spawn(array $args){$p=proc_open($args,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,'/',
 ['PATH'=>'/usr/sbin:/usr/bin:/sbin:/bin','LANG'=>'C.UTF-8','LC_ALL'=>'C.UTF-8'],['bypass_shell'=>true]);nx_need(is_resource($p),'owner-process-start');foreach($pipes as$pipe)stream_set_blocking($pipe,false);return [$p,$pipes];}
function nx_collect(array $child,string $input,int $seconds,int $maximum=262144):array{
 [$p,$pipes]=$child;$pending=$input;$out='';$err='';$exit=-1;$deadline=microtime(true)+$seconds;
 try{do{
  if(isset($pipes[0])){if($pending!==''){$n=fwrite($pipes[0],substr($pending,0,16384));nx_need($n!==false,'owner-input-write');$pending=substr($pending,$n);}if($pending===''){fclose($pipes[0]);unset($pipes[0]);}}
  $out.=stream_get_contents($pipes[1]);$err.=stream_get_contents($pipes[2]);nx_need(strlen($out)<=$maximum&&strlen($err)<=8192,'owner-process-output');$s=proc_get_status($p);
  if(!$s['running']){$exit=$s['exitcode'];break;}nx_need(microtime(true)<$deadline,'owner-process-timeout');usleep(10000);
 }while(true);$out.=stream_get_contents($pipes[1]);$err.=stream_get_contents($pipes[2]);nx_need(strlen($out)<=$maximum&&strlen($err)<=8192&&$pending==='','owner-process-output');
 }finally{
  $s=proc_get_status($p);
  if($s['running']){
   proc_terminate($p,15);$reap=microtime(true)+0.25;
   do{usleep(2000);$s=proc_get_status($p);}while($s['running']&&microtime(true)<$reap);
   if($s['running']){proc_terminate($p,9);$reap=microtime(true)+2.;do{usleep(2000);$s=proc_get_status($p);}while($s['running']&&microtime(true)<$reap);}
  }
  foreach($pipes as$pipe)fclose($pipe);
  nx_need(!$s['running'],'owner-process-cleanup-unconfirmed');
  $closed=proc_close($p);
 }if($exit<0)$exit=$closed;return ['exit'=>$exit,'out'=>$out,'err'=>$err];
}
function nx_run(array $args,string $input='',int $seconds=30,int $maximum=262144):array{return nx_collect(nx_spawn($args),$input,$seconds,$maximum);}
function nx_runtime():array{
 nx_need(PHP_SAPI==='cli'&&posix_geteuid()===0&&strtolower(gethostname())==='reach-host','nexus-root-console-required');nx_path(NX_ROOT,true,0700);nx_path(NX_ROOT.'/runtime',true,0700);
 $manifest=nx_json(nx_read(NX_ROOT.'/runtime/runtime-files.json',16384));nx_fields($manifest,['version','files']);nx_need(($manifest['version']??null)===1&&is_array($manifest['files']),'owner-runtime-manifest');
 $names=array_keys($manifest['files']);sort($names);$expected=NX_RUNTIME;sort($expected);nx_need($names===$expected,'owner-runtime-files');
 foreach(NX_RUNTIME as$name){$sha=nx_hex($manifest['files'][$name]);nx_need(hash('sha256',nx_read(NX_ROOT.'/runtime/'.$name))===$sha,'owner-runtime-pin');}
 $config=nx_json(nx_read(NX_ROOT.'/config.json',16384));nx_fields($config,['version','owner_gate_sha256']);nx_need($config['version']===1,'owner-config-version');nx_hex($config['owner_gate_sha256']);return $config;
}
function nx_packet(array $v):array{
 nx_fields($v,['arguments','operation','operation_id','script_base64','script_sha256','timeout_seconds','version','vm_id']);nx_need($v['version']===2&&$v['operation']==='execute-owner-vm'&&is_string($v['vm_id'])&&isset(NX_TARGETS[$v['vm_id']]),'owner-vm-target');nx_hex($v['operation_id'],32);nx_hex($v['script_sha256']);
 nx_need(is_string($v['script_base64']),'owner-script-encoding');$script=base64_decode($v['script_base64'],true);nx_need(is_string($script)&&strlen($script)>0&&strlen($script)<=16384&&base64_encode($script)===$v['script_base64']&&!str_contains($script,"\0")&&preg_match('//u',$script)===1&&hash('sha256',$script)===$v['script_sha256'],'owner-script-binding');
 nx_need(is_array($v['arguments'])&&array_is_list($v['arguments'])&&count($v['arguments'])<=32,'owner-arguments');$total=0;foreach($v['arguments']as$a){nx_need(is_string($a)&&strlen($a)<=8192&&!str_contains($a,"\0")&&preg_match('//u',$a)===1,'owner-argument');$total+=strlen($a);}nx_need($total<=32768&&is_int($v['timeout_seconds'])&&$v['timeout_seconds']>=1&&$v['timeout_seconds']<=300,'owner-bounds');ksort($v);nx_need(strlen(nx_bytes($v))<=262144,'owner-request-bound');return $v;
}
