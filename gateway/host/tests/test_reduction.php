<?php
/* Execute the real reduction-store functions against one new synthetic tree.
 * No Core command/VM/API/socket is called. Admission flock has its own fixture. */
declare(strict_types=1);
if(PHP_SAPI!=='cli'||posix_geteuid()!==0||$argc!==1)throw new RuntimeException('native-root-fixture-only');
$root=sys_get_temp_dir().'/reach-reduction-fixture-'.bin2hex(random_bytes(8));mkdir($root,0700);
define('NX_ROOT',$root);define('WG_STATE',$root.'/state/workflows');mkdir($root.'/state',0700);mkdir($root.'/state/sessions',0700);$checks=0;$barriers=0;
function nx_need(bool $v,string $why):void{if(!$v)throw new RuntimeException($why);}
function wg_need(bool $v,string $why):void{nx_need($v,$why);}
function nx_id(string $v):string{nx_need(preg_match('/^[A-Za-z0-9_.:-]{1,255}$/D',$v)===1,'fixture-id');return$v;}
function nx_hex(string $v,int $n=64):string{nx_need(preg_match('/^[a-f0-9]{'.$n.'}$/D',$v)===1,'fixture-hex');return$v;}
function nx_path(string $p,bool $dir=false,?int $mode=null):void{nx_need(str_starts_with($p,NX_ROOT.'/')&&!str_contains($p,'..')&&!is_link($p)&&($dir?is_dir($p):is_file($p)),'fixture-no-production-path');}
function nx_dir(string $p):void{nx_need(str_starts_with($p,NX_ROOT.'/'),'fixture-root');if(!file_exists($p))mkdir($p,0700);}
function nx_read(string $p,int $max=262144):string{nx_path($p);$s=file_get_contents($p);nx_need(is_string($s)&&strlen($s)<=$max,'fixture-bound');return$s;}
function nx_json(string $v,int $max=262144):array{nx_need(strlen($v)<=$max,'fixture-json');return json_decode($v,true,32,JSON_THROW_ON_ERROR);}
function nx_atomic(string $p,array $v):void{nx_need(str_starts_with($p,WG_STATE.'/'),'fixture-private-only');$temp=$p.'.tmp';$f=fopen($temp,'x+b');fwrite($f,json_encode($v,JSON_THROW_ON_ERROR));fflush($f);fsync($f);fclose($f);chmod($temp,0600);rename($temp,$p);}
function wg_fenced(callable $f):mixed{global$barriers;$barriers++;return$f();}
function wg_stamp(int $pid):array{throw new RuntimeException('synthetic-dead-old-console');}
function check(bool $v,string $why):void{global$checks;nx_need($v,$why);$checks++;}
$source=file_get_contents(dirname(__DIR__).'/core/workflow_guard.php');
$functions=['wg_sync','wg_init','wg_write','wg_session_path','wg_scope','wg_scope_end_path','wg_start_intent','wg_register','wg_session','wg_end_generation','wg_end_scope','wg_revoke_scope','wg_pending_ends','wg_ack_end'];
foreach($functions as$name){$a=strpos($source,'function '.$name.'(');$b=strpos($source,"\nfunction ",$a+1);nx_need($a!==false,'fixture-exact-function');eval(substr($source,$a,($b===false?strlen($source):$b)-$a));}
wg_init();$binding=['subject'=>'424242','vm_id'=>'vm-alpha','control_id'=>str_repeat('1',32),'lease_id'=>str_repeat('2',32),'gateway_epoch'=>str_repeat('3',32),'expires_at'=>1234];
$sid='mcp-synthetic-old';$gen=str_repeat('a',32);$session=['version'=>1,'session_id'=>$sid,'generation'=>$gen,'binding'=>$binding,'anchor'=>[],'runtime_sha256'=>str_repeat('0',64),'revision'=>0,'console'=>['pid'=>123456,'created'=>'1'],'ended'=>false,'permission_mode'=>'workflow'];wg_write(wg_session_path($sid),$session);
wg_end_generation($sid,$gen,'Synthetic owner end');$pending=wg_pending_ends();check(count($pending)===1,'end-persists-pending');check(wg_session($sid,$gen)['ended']===true,'local-tombstone-first');check($barriers===1,'reduction-linearization-barrier');
$record=$pending[0];$bad=false;try{wg_ack_end($record,['session'=>['version'=>1,'session_id'=>$sid,'active'=>false,'generation'=>str_repeat('b',32)]]);}catch(RuntimeException $ignored){$bad=true;}check($bad&&count(wg_pending_ends())===1,'wrong-generation-cannot-ack');
wg_ack_end($record,['session'=>['version'=>1,'session_id'=>$sid,'active'=>false,'generation'=>$gen]]);check(wg_pending_ends()===[],'exact-end-ack-clears-pending');
$new=$session;$new['session_id']='mcp-synthetic-new';$new['generation']=str_repeat('c',32);$new['permission_mode']='ask_each';$new['console']=['pid'=>123457,'created'=>'2'];$new['ended']=true;wg_write(wg_session_path($new['session_id']),$new);
// Reconstruct the deliberate tombstone-before-outbox crash gap.
$pending=wg_pending_ends();check(count($pending)===1&&$pending[0]['generation']===$new['generation'],'crash-gap-recovered-exact-generation');
wg_ack_end($record,['session'=>['version'=>1,'session_id'=>$sid,'active'=>false,'generation'=>$gen]]);check(count(wg_pending_ends())===1,'old-ack-never-clears-replacement');
// A lost Core start acknowledgement resolves only its captured SID/console.
$orphan=['version'=>1,'session_id'=>'mcp-synthetic-orphan','binding'=>$binding,'revision'=>0,'console'=>['pid'=>123458,'created'=>'3'],'cancelled'=>true];wg_write(WG_STATE.'/start-'.hash('sha256',$orphan['session_id']).'.json',$orphan);file_put_contents(NX_ROOT.'/state/sessions/'.hash('sha256',$orphan['session_id']).'.json',json_encode(['session_id'=>$orphan['session_id'],'generation'=>str_repeat('d',32),'console'=>$orphan['console']]));check(count(wg_pending_ends())===2,'lost-start-ack-reduces-old-generation');
wg_end_scope($binding,'Synthetic released claim');check(is_file(wg_scope_end_path($binding)),'released-scope-permanent-tombstone');$refused=false;try{wg_register('mcp-synthetic-future',str_repeat('e',32),['binding'=>$binding,'anchor'=>[],'runtime_sha256'=>str_repeat('0',64)],1);}catch(RuntimeException $ignored){$refused=true;}check($refused,'released-control-never-registers-again');
echo json_encode(['ok'=>true,'checks'=>$checks,'actual_reduction_store_functions'=>true,'native_core_commands'=>0,'guest_calls'=>0,'production_paths_accessed'=>false,'temporary_fixture'=>$root],JSON_THROW_ON_ERROR)."\n";
