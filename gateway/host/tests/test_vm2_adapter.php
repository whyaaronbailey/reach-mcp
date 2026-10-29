<?php
declare(strict_types=1);
require __DIR__.'/../core/nexus_vm2.php';
$n=0;
function check(bool $v):void{global $n;if(!$v)throw new RuntimeException('vm2-fixture');$n++;}
function refused(array $v,?string $sha=null):void{$raw=nx_bytes($v);try{nv2_request($raw,$sha??hash('sha256',$raw));}catch(Throwable $e){check(true);return;}check(false);}
$script='Write-Output fixture';
$v=nx_packet(['version'=>2,'operation'=>'execute-owner-vm','operation_id'=>str_repeat('a',32),'vm_id'=>'vm-gamma','script_base64'=>base64_encode($script),'script_sha256'=>hash('sha256',$script),'arguments'=>[],'timeout_seconds'=>60]);
$raw=nx_bytes($v);check(nv2_request($raw,hash('sha256',$raw))===$v);
foreach(['vm-beta','vm-alpha','vm-unknown']as$vm){$x=$v;$x['vm_id']=$vm;refused($x);}
$x=$v;$x['version']=3;refused($x);
$x=$v;$x['operation']='provision';refused($x);
$x=$v;$x['approved']=true;refused($x);
refused($v,str_repeat('0',64));
$x=$v;$x['script_sha256']=str_repeat('0',64);refused($x);
$x=$v;$x['arguments']=["bad\0value"];refused($x);
check(NX_TARGETS['vm-gamma']===['uuid'=>'435cefb1-5990-5dfa-9f0c-06ddd5cee23b','sid'=>'S-1-5-18']);
echo json_encode(['ok'=>true,'vm2_adapter_tests'=>$n])."\n";
