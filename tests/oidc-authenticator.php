<?php
declare(strict_types=1);

// Focused RP regression. The real native issuer is covered separately in staging.
define('UCRM_OIDC_FIXTURES_ONLY', true);
require __DIR__.'/core-unit.php';

try {
    $x=fixture();$uid=array_key_first($x['adapter']->users);
    $x['adapter']->users[$uid]['totpAuthEnabled']=true;
    $before=$x['adapter']->users[$uid];
    $a=login($x);callback($x,$a);
    check('verified callback alone issues no session',$x['adapter']->issues===0);
    $m=$x['app']->handoff($a['browser'],$a['start']['flowId'],$a['audit'],null);
    check('verified OIDC completes without a native OTP',$m['kind']==='session'&&count($x['adapter']->challenges)===0);
    check('account authenticator and permissions unchanged',$x['adapter']->users[$uid]===$before);
    check('native session persisted before delivery',$x['store']->one('SELECT COUNT(*) AS n FROM sessions')['n']===1);
    denied('completed handoff cannot issue twice',fn()=>$x['app']->handoff($a['browser'],$a['start']['flowId'],$a['audit'],null),'FLOW_USED');
    $binding=$x['app']->records($x['admin'],'bindings',[])['items'][0];
    $x['app']->unlink($x['admin'],['bindingId'=>$binding['id'],'expectedVersion'=>$binding['version']]);
    check('native session revocation still works',count($x['adapter']->sessions)===0);

    foreach (['signature','nonce','email','disabled','unvalidated'] as $case) {
        $x=fixture();$uid=array_key_first($x['adapter']->users);$x['adapter']->users[$uid]['totpAuthEnabled']=true;
        $claims=$case==='nonce'?['nonce'=>'incorrect']:[];
        $info=$case==='email'?['email_verified'=>false]:[];
        $a=login($x,$claims,$info);
        if($case==='signature')$x['provider']->key=openssl_pkey_new(['private_key_bits'=>2048,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);
        if($case==='disabled')$x['adapter']->users[$uid]['disabled']=true;
        if($case==='unvalidated'){
            denied('unvalidated flow cannot request native issuance',fn()=>$x['app']->handoff($a['browser'],$a['start']['flowId'],$a['audit'],null));
        } else {
            denied($case.' still denied on enrolled account',fn()=>callback($x,$a));
        }
        check($case.' cannot issue a native session',$x['adapter']->issues===0&&count($x['adapter']->sessions)===0);
    }
    echo json_encode(['php'=>PHP_VERSION,'passed'=>count($checks),'checks'=>$checks],JSON_PRETTY_PRINT),"\n";
} catch(Throwable $e) {
    echo json_encode(['failure'=>$e->getMessage(),'checks'=>$checks],JSON_PRETTY_PRINT),"\n";exit(1);
}
