<?php
/* Exact production fence functions; only constants point at new synthetic files.
 * Root-only native fixture; no production mount, registry, socket or VM call. */
declare(strict_types=1);
if(PHP_SAPI!=='cli'||posix_geteuid()!==0||$argc!==1)throw new RuntimeException('native-root-fixture-only');
$root=sys_get_temp_dir().'/reach-claim-fence-fixture-'.bin2hex(random_bytes(8));mkdir($root,0700);
define('WG_RUN',$root.'/run');define('WG_FENCE',WG_RUN.'/claim-fence.lock');mkdir(WG_RUN,0750);chgrp(WG_RUN,10008);chmod(WG_RUN,0750);file_put_contents(WG_FENCE,'');chgrp(WG_FENCE,10008);chmod(WG_FENCE,0640);
function nx_need(bool $v,string $why):void{if(!$v)throw new RuntimeException($why);}
function wg_need(bool $v,string $why):void{nx_need($v,$why);}
$source=file_get_contents(dirname(__DIR__).'/core/workflow_guard.php');
$a=strpos($source,'function wg_fence_file(');$b=strpos($source,'function wg_runtime(',$a);nx_need($a!==false&&$b!==false,'exact-function-markers');eval(substr($source,$a,$b-$a));
$entered=0;wg_fenced(static function()use(&$entered){$entered++;$f=fopen(WG_FENCE,'rb');try{nx_need(!flock($f,LOCK_EX|LOCK_NB),'second-open-must-block');}finally{fclose($f);}});nx_need($entered===1,'actual-fence-callback');$f=fopen(WG_FENCE,'rb');nx_need(flock($f,LOCK_EX|LOCK_NB),'lock-released-after-spawn');fclose($f);
try{wg_fenced(static function(){throw new RuntimeException('synthetic-spawn-refused');});}catch(RuntimeException $e){nx_need($e->getMessage()==='synthetic-spawn-refused','expected-throw');}
$f=fopen(WG_FENCE,'rb');nx_need(flock($f,LOCK_EX|LOCK_NB),'lock-released-on-error');fclose($f);
chmod(WG_FENCE,0660);$refused=false;try{wg_fenced(static fn()=>true);}catch(RuntimeException $e){$refused=true;}nx_need($refused,'group-writable-fence-refused');chmod(WG_FENCE,0640);
echo json_encode(['ok'=>true,'actual_readonly_fd_flock'=>true,'release_on_callback_error'=>true,'wrong_metadata_refused'=>true,'uid10008_readonly_bind_mount_tested'=>false,'guest_calls'=>0,'production_paths_accessed'=>false,'temporary_fixture'=>$root],JSON_THROW_ON_ERROR)."\n";
