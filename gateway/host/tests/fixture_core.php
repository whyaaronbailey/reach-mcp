<?php
/* Disposable broker protocol fixture. Never installed as the production core.
 * It has no VM transport, key access, Docker call or external network. */
declare(strict_types=1);
$v=json_decode(stream_get_contents(STDIN,262145),true,32,JSON_THROW_ON_ERROR);$command=$v['command'];
if(isset($argv[1]))file_put_contents($argv[1],json_encode(['command'=>$command,'operation_id'=>$v['operation_id']??null])."\n",FILE_APPEND|LOCK_EX);
if($command==='end'){if(file_exists($argv[1].'.fail-end-once')){unlink($argv[1].'.fail-end-once');echo '{"ok":false}';exit(1);}echo json_encode(['ok'=>true,'session'=>['version'=>1,'session_id'=>$v['session_id'],'generation'=>$v['generation'],'active'=>false,'mode'=>'ask_each']]);exit;}
if($command==='start'){echo json_encode(['ok'=>true,'session'=>['generation'=>substr(hash('sha256',$v['session_id']),0,32),'mode'=>'ask_each']]);exit;}
if($command==='prepare'){$id=bin2hex(random_bytes(16));$r=['version'=>2,'operation'=>'execute-owner-vm','vm_id'=>$v['vm_id'],'operation_id'=>$id,'script_base64'=>$v['script_base64'],'script_sha256'=>hash('sha256',base64_decode($v['script_base64'])),'arguments'=>$v['arguments'],'timeout_seconds'=>$v['timeout_seconds']];ksort($r);$hash=hash('sha256',json_encode($r,JSON_UNESCAPED_SLASHES));$file=$argv[1].'.'.$id;file_put_contents($file,json_encode(['request'=>$r,'hash'=>$hash]));echo json_encode(['ok'=>true,'request'=>$r,'request_sha256'=>$hash]);exit;}
if($command==='allow-session'&&str_contains($v['approval_reference'],'slow'))usleep(300000);
if($command==='execute'){$entry=json_decode(file_get_contents($argv[1].'.'.$v['operation_id']),true);$r=$entry['request'];if(str_contains(base64_decode($r['script_base64']),'fixture:sleep'))usleep(1200000);echo json_encode(['version'=>2,'operation'=>'execute-owner-vm','vm_id'=>$r['vm_id'],'operation_id'=>$r['operation_id'],'request_sha256'=>$v['request_sha256'],'script_sha256'=>$r['script_sha256'],'state'=>'completed','exit_code'=>0,'output'=>'fixture-only','administrator'=>true,'automatic_retry'=>false]);exit;}
echo json_encode(['ok'=>true,'session'=>['mode'=>$command==='allow-session'?'session':'ask_each']]);
