<?php
/* Exact production dispatch, reduction, process collector and flock functions.
 * A synthetic current-claim predicate and harmless local child replace the VM
 * and Docker adapter. No production paths, grants or guest calls. */
declare(strict_types=1);
if(PHP_SAPI!=='cli'||posix_geteuid()!==0||$argc!==1)throw new RuntimeException('root-fixture-only');
umask(0077);
$root='/root/reach-r9-dispatch-fixture-'.bin2hex(random_bytes(12));mkdir($root,0700);
define('NX_ROOT',$root);define('WG_RUN',$root.'/run');define('WG_FENCE',WG_RUN.'/claim-fence.lock');define('WG_STATE',$root.'/state/workflows');
mkdir($root.'/state',0700);mkdir($root.'/state/sessions',0700);mkdir(WG_RUN,0750);chgrp(WG_RUN,10008);chmod(WG_RUN,0750);
$f=fopen(WG_FENCE,'x+b');fclose($f);chgrp(WG_FENCE,10008);chmod(WG_FENCE,0640);
$common=file_get_contents(dirname(__DIR__).'/core/nexus_common.php');eval(substr($common,strpos($common,'function nx_need(')));
$source=file_get_contents(dirname(__DIR__).'/core/workflow_guard.php');
foreach(['wg_need','wg_sync','wg_init','wg_write','wg_session_path','wg_scope','wg_scope_end_path','wg_stamp','wg_fence_file','wg_fenced','wg_session','wg_capture_operation','wg_dispatch','wg_end_generation','wg_pending_ends','wg_ack_end']as$name){
 $a=strpos($source,'function '.$name.'(');$b=strpos($source,"\nfunction ",$a+1);nx_need($a!==false,'exact-function');eval(substr($source,$a,($b===false?strlen($source):$b)-$a));
}
function wg_workflow_verified():bool{return true;}
function wg_verify_unlocked(array $binding):array{
 $v=nx_json(nx_read(NX_ROOT.'/current.json'));
 if(file_exists(NX_ROOT.'/slow')){file_put_contents(NX_ROOT.'/entered','yes');usleep(700000);}
 nx_need($v['binding']===$binding,'synthetic-replaced-claim');
 return $v;
}
$checks=0;$times=[];
function check(bool $v,string $why):void{global$checks;nx_need($v,$why);$checks++;}
function refused(callable $f,string $expected):void{$e='';try{$f();}catch(RuntimeException $x){$e=$x->getMessage();}check($e===$expected,$expected);}
$binding=['subject'=>'424242','vm_id'=>'vm-beta','control_id'=>str_repeat('1',32),'lease_id'=>str_repeat('2',32),'gateway_epoch'=>str_repeat('3',32),'expires_at'=>time()+600];
$current=['binding'=>$binding,'anchor'=>['lease'=>'test'],'runtime_sha256'=>str_repeat('a',64),'lease_expires_at'=>time()+600,'reservation_expires_at'=>time()+600];
nx_new($root.'/current.json',nx_bytes($current));wg_init();
$console=wg_stamp(posix_getpid());$sid='mcp-fixture';$gen=str_repeat('b',32);$sha=str_repeat('c',64);
$session=['version'=>1,'session_id'=>$sid,'generation'=>$gen,'binding'=>$binding,'anchor'=>$current['anchor'],'runtime_sha256'=>$current['runtime_sha256'],'revision'=>0,'console'=>$console,'ended'=>false,'permission_mode'=>'workflow'];
wg_write(wg_session_path($sid),$session);
function admit(string $op):array{global$sid,$gen,$sha,$console;return wg_dispatch($sid,$gen,$op,$sha,$console,static fn()=>nx_spawn(['/usr/bin/php','-r','echo "admitted";']));}
for($n=1;$n<=3;$n++){$op=str_pad((string)$n,32,'0',STR_PAD_LEFT);wg_capture_operation($sid,$gen,$op,$sha,0,true);$r=nx_collect(admit($op),'',2);check($r===['exit'=>0,'out'=>'admitted','err'=>''],'unlimited-operation-'.$n);}
$op=str_repeat('d',32);wg_capture_operation($sid,$gen,$op,$sha,0,true);
wg_end_generation($sid,$gen,'synthetic owner revoke');refused(static fn()=>admit($op),'workflow-ended-before-dispatch');
// A revocation acknowledges only after an admission already holding the fence.
$sid='mcp-race';$session['session_id']=$sid;wg_write(wg_session_path($sid),$session);$op=str_repeat('e',32);wg_capture_operation($sid,$gen,$op,$sha,0,true);file_put_contents($root.'/slow','yes');
$pid=pcntl_fork();nx_need($pid>=0,'fixture-fork');
if($pid===0){try{$r=nx_collect(admit($op),'',3);nx_need($r['exit']===0&&$r['out']==='admitted','race-admission');exit(0);}catch(Throwable $e){fwrite(STDERR,$e->getMessage());exit(1);}}
$end=microtime(true)+3;while(!file_exists($root.'/entered')){nx_need(microtime(true)<$end,'race-ready-timeout');usleep(2000);}
$t=microtime(true);wg_end_generation($sid,$gen,'synthetic concurrent revoke');$elapsed=microtime(true)-$t;$times['revoke_barrier_seconds']=$elapsed;check($elapsed>=0.5&&$elapsed<2,'revoke-waits-for-admitted-dispatch');pcntl_waitpid($pid,$status);check(pcntl_wifexited($status)&&pcntl_wexitstatus($status)===0,'admitted-command-finishes');unlink($root.'/slow');refused(static fn()=>admit($op),'workflow-ended-before-dispatch');
// An unrevoked session still refuses expired, replaced and stale-generation work.
$sid='mcp-new';$session['session_id']=$sid;wg_write(wg_session_path($sid),$session);$op=str_repeat('f',32);wg_capture_operation($sid,$gen,$op,$sha,0,true);
$v=$current;$v['lease_expires_at']=time()-1;nx_atomic($root.'/current.json',$v);refused(static fn()=>admit($op),'workflow-expired-at-dispatch');
$v=$current;$v['binding']['control_id']=str_repeat('4',32);nx_atomic($root.'/current.json',$v);refused(static fn()=>admit($op),'synthetic-replaced-claim');nx_atomic($root.'/current.json',$current);
$v=wg_session($sid,$gen);$v['revision']=1;wg_write(wg_session_path($sid),$v);refused(static fn()=>admit($op),'workflow-operation-association');
// Dead broker process: exact persisted generation is ended on reconstruction.
$pid=pcntl_fork();nx_need($pid>=0,'fixture-fork');if($pid===0){sleep(3);exit(0);}
$dead=wg_stamp($pid);posix_kill($pid,9);pcntl_waitpid($pid,$status);$sid='mcp-dead-console';$session['session_id']=$sid;$session['console']=$dead;wg_write(wg_session_path($sid),$session);$ends=wg_pending_ends();check(wg_session($sid,$gen)['ended']===true,'restart-old-console-reduced');check(count(array_filter($ends,static fn($v)=>$v['session_id']==='mcp-dead-console'&&$v['generation']===$gen))===1,'restart-exact-generation-outbox');
// Real process collector: ignored TERM cannot hold the admission lock forever.
$child=nx_spawn(['/usr/bin/php','-r','pcntl_async_signals(true);pcntl_signal(SIGTERM,SIG_IGN);while(true){usleep(10000);}']);$childpid=proc_get_status($child[0])['pid'];$t=microtime(true);refused(static fn()=>wg_fenced(static fn()=>nx_collect($child,'',1)),'owner-process-timeout');$times['term_ignored_cleanup_seconds']=microtime(true)-$t;check($times['term_ignored_cleanup_seconds']<3.5&&!posix_kill($childpid,0),'timeout-child-reaped');check(wg_fenced(static fn()=>true),'collector-failure-unlocks-fence');
$child=nx_spawn(['/usr/bin/php','-r','echo str_repeat("x",4096);']);refused(static fn()=>nx_collect($child,'',2,128),'owner-process-output');
echo json_encode(['ok'=>true,'checks'=>$checks,'actual_dispatch_and_collector_functions'=>true,'synthetic_claim_adapter'=>true,'guest_calls'=>0,'production_paths_accessed'=>false,'measurements'=>$times,'fixture'=>$root],JSON_THROW_ON_ERROR)."\n";
