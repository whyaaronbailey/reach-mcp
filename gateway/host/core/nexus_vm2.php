<?php
/* VM-GAMMA guest execution only. The version-3 provisioning selector is never
 * called. Permission is checked by nexus_owner before this transport starts. */
declare(strict_types=1);
require_once __DIR__.'/nexus_common.php';
const NV2_GUEST='/var/lib/reach-owner/guest-adapter/vm-gamma/owner-vm-exec.php';
const NV2_GUEST_SHA='0000000000000000000000000000000000000000000000000000000000000000';
function nv2_request(string $raw,string $expected):array{
 nx_hex($expected);$request=nx_packet(nx_json($raw));
 nx_need($request['vm_id']==='vm-gamma'&&nx_bytes($request)===$raw&&hash('sha256',$raw)===$expected,'vm2-captured-guest-request');
 return $request;
}
function nv2_main(array $argv,string $raw):array{
 nx_need(count($argv)===3&&$argv[1]==='--request-sha256'&&__FILE__===NX_ROOT.'/runtime/nexus_vm2.php','fixed-vm2-guest-transport');
 nv2_request($raw,$argv[2]);$config=nx_runtime();
 nx_need(hash('sha256',nx_read(NX_GATE))===$config['owner_gate_sha256'],'existing-owner-gate-changed');
 nx_need(hash('sha256',nx_read(NV2_GUEST,131072))===NV2_GUEST_SHA,'vm2-guest-executor-pin');
 // Loading the existing entry defines the protected boot-mirror recovery
 // helpers; its CLI and provisioning branches do not run when included here.
 require_once NX_GATE;
 og_restore_legacy();
 require_once NV2_GUEST;
 return owner_vm_main($raw);
}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__){
 try{$raw=stream_get_contents(STDIN,262145);nx_need(is_string($raw),'vm2-owner-input');echo nx_bytes(nv2_main($argv,$raw))."\n";}
 catch(Throwable $e){echo '{"ok":false,"reason":"vm2-guest-transport-refused","automatic_retry":false}'."\n";exit(1);}
}
