<?php
/* Disposable PHP process fixtures only. Never install as the Root Core. */
declare(strict_types=1);
require dirname(__DIR__).'/broker/owner_broker.php';
$dir=sys_get_temp_dir().'/reach-workflow-fixture-'.bin2hex(random_bytes(8));mkdir($dir,0700);$log=$dir.'/events.jsonl';$checks=0;
function check(bool $v,string $name):void{global$checks;mb_need($v,'fixture-'.$name);$checks++;}
function events(string $command):array{global$log;if(!file_exists($log))return[];return array_values(array_filter(array_map(static fn($v)=>json_decode($v,true),file($log,FILE_IGNORE_NEW_LINES)),static fn($v)=>$v['command']===$command));}
function tick(ReachOwnerBroker $b,callable $done):void{$end=microtime(true)+5;while(!$done()){$b->sweep();$b->driveTasks();mb_need(microtime(true)<$end,'fixture-timeout');usleep(2000);}}
function req(ReachOwnerBroker $b,array $v):array{static$id=0;$id++;$b->clients[$id]=['out'=>null,'deadline'=>0];$b->request($v,$id,10008);tick($b,static fn()=>$b->clients[$id]['out']!==null);$r=json_decode($b->clients[$id]['out'],true,32,JSON_THROW_ON_ERROR);unset($b->clients[$id]);return$r;}
function frame(string $command,array $binding,array $fields=[]):array{return['version'=>1,'command'=>$command,'binding'=>$binding,...$fields];}
function prep(ReachOwnerBroker $b,array $binding):array{return req($b,frame('prepare',$binding,['script_base64'=>base64_encode('synthetic:no-vm-transport'),'arguments'=>[],'timeout_seconds'=>1]));}
function execute(ReachOwnerBroker $b,array $binding,array $p,?string $choice='once',?string $ref='synthetic:native-form'):array{return req($b,frame('execute',$binding,['operation_id'=>$p['operation_id'],'request_sha256'=>$p['request_sha256'],'approval_nonce'=>$p['approval_nonce'],'choice'=>$choice,'approval_reference'=>$ref]));}
function complete(ReachOwnerBroker $b,string $job):void{tick($b,static fn()=>($b->jobs[$job]['state']??null)!=='running');}
$now=1000.;$expiry=1005.;$valid=true;$clock=static function()use(&$now){return$now;};
$binding=['subject'=>'424242','vm_id'=>'vm-alpha','control_id'=>str_repeat('1',32),'lease_id'=>str_repeat('2',32),'gateway_epoch'=>str_repeat('3',32),'expires_at'=>$expiry];
$verify=static function(array $b)use(&$valid,&$expiry){mb_need($valid,'synthetic-claim-ended');$b['expires_at']=$expiry;return['binding'=>$b,'anchor'=>['owner_decision'=>'fixed'],'runtime_sha256'=>str_repeat('0',64)];};
$b=new ReachOwnerBroker($clock,[PHP_BINARY,__DIR__.'/fixture_core.php',$log],$verify,true);
$p=prep($b,$binding);check($p['workflow_release_verified']===true&&$p['permission_mode']==='ask_each','verified-fixture-asks-human');$r=execute($b,$binding,$p,'workflow');complete($b,$r['job_id']);
for($i=0;$i<3;$i++){$p=prep($b,$binding);check($p['permission_mode']==='workflow','workflow-retained-'.$i);$r=execute($b,$binding,$p,null,null);complete($b,$r['job_id']);check($b->jobs[$r['job_id']]['state']==='completed','multiple-workflow-operations-'.$i);}
// A real claim renewal survives a lost broker renewal notification.
$expiry=1010.;$now=1006.;$b->sweep();$binding['expires_at']=$expiry;$p=prep($b,$binding);check($p['permission_mode']==='workflow','authoritative-renewal-survives-lost-notice');
$key=mb_scope($binding);$oldSid=$b->scopes[$key]['session_id'];$oldGen=$b->scopes[$key]['generation'];$oldPrepared=$p;
file_put_contents($log.'.fail-end-once','synthetic');$r=req($b,frame('revoke',$binding,['reference'=>'synthetic:owner-revoke']));check($r['durable_reduction_accepted']===true&&$b->scopes[$key]['mode']==='ask_each','revoke-local-immediate');tick($b,static fn()=>count(events('end'))===1&&!$b->tasks);check($b->scopes[$key]['generation_ended']===false&&$b->scopes[$key]['rotation_pending']===true,'failed-end-not-acknowledged');
$now+=2;tick($b,static fn()=>!$b->scopes[$key]['rotation_pending']);$p=prep($b,$binding);check($p['permission_mode']==='ask_each'&&$b->scopes[$key]['session_id']!==$oldSid&&$b->scopes[$key]['generation']!==$oldGen,'revoke-rotates-exact-generation');check($b->scopes[$key]['generation_ended']===false,'replacement-not-marked-ended');$r=execute($b,$binding,$oldPrepared,null,null);check($r['ok']===false,'old-nonce-cannot-use-replacement');
// Release while the old native-approval callback is still queued.
$before=count(events('execute'));$r=execute($b,$binding,$p,'workflow','synthetic:slow-allow');req($b,frame('end',$binding,['reference'=>'synthetic:release']));complete($b,$r['job_id']);check($b->jobs[$r['job_id']]['state']==='failed'&&count(events('execute'))===$before,'queued-approval-after-release-no-dispatch');
// Claim ends in the registry while its separate broker end message is lost.
$next=$binding;$next['control_id']=str_repeat('4',32);$p=prep($b,$next);$r=execute($b,$next,$p,'workflow','synthetic:slow-allow');$valid=false;complete($b,$r['job_id']);check($b->jobs[$r['job_id']]['state']==='failed'&&count(events('execute'))===$before,'fresh-dispatch-claim-check-blocks-lost-end-message');
// Owner dashboard: list is read-only; revoke is owner/scope bound and fences queued approvals.
req($b,frame('end',$next,['reference'=>'synthetic:lost-claim-ended']));
$valid=true;$expiry=$now+500;
$third=$binding;$third['control_id']=str_repeat('5',32);$third['expires_at']=$expiry;
$fourth=$third;$fourth['control_id']=str_repeat('6',32);
foreach([$third,$fourth]as$target){$p=prep($b,$target);$r=execute($b,$target,$p,'workflow');complete($b,$r['job_id']);}
$before=count(events('execute'));$listed=req($b,['version'=>1,'command'=>'sessions','subject'=>$binding['subject']]);
check($listed['ok']===true&&count($listed['sessions'])===2,'dashboard-lists-only-active-grants');
check(count(events('execute'))===$before,'list-cannot-execute');
$other=req($b,['version'=>1,'command'=>'sessions','subject'=>'999999']);check($other['sessions']===[],'dashboard-owner-isolation');
$p3=prep($b,$third);$p4=prep($b,$fourth);
$r=req($b,['version'=>1,'command'=>'revoke-sessions','subject'=>$binding['subject'],'scope'=>mb_scope($third),'reference'=>'synthetic:owner-page']);
check($r['durable_reduction_accepted']===true&&$b->scopes[mb_scope($third)]['mode']==='ask_each'&&$b->scopes[mb_scope($fourth)]['mode']==='workflow','revoke-only-selected-session');
check(execute($b,$third,$p3,null,null)['ok']===false,'revoked-session-prepared-operation-refused');
$r=execute($b,$fourth,$p4,null,null);complete($b,$r['job_id']);check($b->jobs[$r['job_id']]['state']==='completed','other-session-retains-permission');
$queued=$third;$queued['control_id']=str_repeat('7',32);$p=prep($b,$queued);$r=execute($b,$queued,$p,'workflow','synthetic:slow-allow');
$before=count(events('execute'));$all=req($b,['version'=>1,'command'=>'revoke-sessions','subject'=>$binding['subject'],'scope'=>'all','reference'=>'synthetic:owner-revoke-all']);
complete($b,$r['job_id']);check($all['durable_reduction_accepted']===true&&count(events('execute'))===$before&&$b->jobs[$r['job_id']]['state']==='failed','revoke-all-blocks-late-grant-callback');
foreach($b->scopes as$entry)check($entry['mode']==='ask_each','revoke-all-leaves-no-session-grant');
check(req($b,['version'=>1,'command'=>'sessions','subject'=>$binding['subject']])['sessions']===[],'revoked-and-completed-sessions-no-longer-active');
$b->closeAll();$now+=2;tick($b,static fn()=>!$b->tasks);echo json_encode(['ok'=>true,'checks'=>$checks,'synthetic_only'=>true,'guest_calls'=>0,'production_files_modified'=>false,'native_form_acceptance_claimed'=>false,'temporary_fixture'=>$dir],JSON_THROW_ON_ERROR)."\n";
