<?php
declare(strict_types=1);
require getenv('UCRM_OIDC_TEST_AUTOLOAD') ?: __DIR__ . '/../plugin/vendor/autoload.php';
foreach (['AppException','Crypto','Store','Config','HttpClient','Oidc','NativeSession','Logout','Application'] as $class) { require __DIR__ . '/../plugin/src/' . $class . '.php'; }

use UcrmOidc\{AppException,Application,Crypto,Store,Config,HttpClient,Oidc,NativeSession,CachedJwks};
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\{RequestInterface,ResponseInterface};
use Nyholm\Psr7\Response;

$checks = [];
function check(string $name, bool $condition): void {
    global $checks; $checks[] = ['name'=>$name,'passed'=>$condition];
    if (!$condition) { throw new RuntimeException('Failed: ' . $name); }
}
function denied(string $name, callable $fn, ?string $code = null): void {
    try { $fn(); } catch (Throwable $e) { check($name, $code === null || ($e->safeCode ?? '') === $code); return; }
    check($name, false);
}
function uuid(): string { $h=bin2hex(random_bytes(16)); return substr($h,0,8).'-'.substr($h,8,4).'-'.substr($h,12,4).'-'.substr($h,16,4).'-'.substr($h,20); }
function b64(string $s): string { return rtrim(strtr(base64_encode($s),'+/','-_'),'='); }

final class Provider implements ClientInterface {
    public array $codes=[]; public array $used=[]; public array $metadata; public array $jwks; public mixed $key;
    public int $tokenRequests=0; public int $tokenStatus=200; public int $jwksRequests=0;
    public function __construct() {
        $this->key=openssl_pkey_new(['private_key_bits'=>2048,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);
        $d=openssl_pkey_get_details($this->key);
        $this->jwks=['keys'=>[['kty'=>'RSA','kid'=>'test-key','alg'=>'RS256','use'=>'sig','n'=>b64($d['rsa']['n']),'e'=>b64($d['rsa']['e'])]]];
        $this->metadata=['issuer'=>'https://identity.example/oidc','authorization_endpoint'=>'https://identity.example/authorize',
            'token_endpoint'=>'https://identity.example/token','jwks_uri'=>'https://identity.example/jwks','userinfo_endpoint'=>'https://identity.example/userinfo',
            'response_types_supported'=>['code'],'id_token_signing_alg_values_supported'=>['RS256'],'code_challenge_methods_supported'=>['S256'],
            'token_endpoint_auth_methods_supported'=>['client_secret_basic','client_secret_post','none']];
    }
    public function register(array $query, array $claims=[], array $userinfo=[], array $headers=[]): string {
        $code=Crypto::random();
        $base=['iss'=>$this->metadata['issuer'],'sub'=>'subject-1','aud'=>'test-client','exp'=>time()+300,'iat'=>time(),'nonce'=>$query['nonce'],'auth_time'=>time()];
        $this->codes[$code]=['claims'=>array_replace($base,$claims),'userinfo'=>array_replace(['sub'=>'subject-1','email'=>'staff@example.com','email_verified'=>true],$userinfo),
            'query'=>$query,'headers'=>array_replace(['alg'=>'RS256','kid'=>'test-key'],$headers)]; return $code;
    }
    public function sendRequest(RequestInterface $r): ResponseInterface {
        $path=$r->getUri()->getPath(); $status=200;
        if ($path==='/oidc/.well-known/openid-configuration') { $data=$this->metadata; }
        elseif ($path==='/jwks') { ++$this->jwksRequests; $data=$this->jwks; }
        elseif ($path==='/token') {
            ++$this->tokenRequests; parse_str((string)$r->getBody(),$p); $code=$p['code']??'';
            if (!isset($this->codes[$code])||isset($this->used[$code])) { return new Response(400,['Content-Type'=>'application/json'],json_encode(['error'=>'invalid_grant'])); }
            $f=$this->codes[$code];
            if (($p['redirect_uri']??'')!=='https://crm.example'.Config::ENTRY.'?action=callback'
                || b64(hash('sha256',$p['code_verifier']??'',true))!==$f['query']['code_challenge']) { throw new RuntimeException('PKCE/redirect violation'); }
            $this->used[$code]=true;
            $input=b64(json_encode($f['headers'])).'.'.b64(json_encode($f['claims'])); openssl_sign($input,$sig,$this->key,OPENSSL_ALGO_SHA256);
            $data=['access_token'=>$code,'token_type'=>'Bearer','expires_in'=>300,'id_token'=>$input.'.'.b64($sig)]; $status=$this->tokenStatus;
        } elseif ($path==='/userinfo') { $code=substr($r->getHeaderLine('Authorization'),7); $data=$this->codes[$code]['userinfo']; }
        else { throw new RuntimeException('Unexpected endpoint'); }
        return new Response($status,['Content-Type'=>'application/json'],json_encode($data,JSON_THROW_ON_ERROR));
    }
}
final class Adapter {
    // Enable legacyMfa explicitly only for rolling-upgrade challenge coverage.
    public array $users; public array $sessions=[]; public array $challenges=[]; public int $issues=0; public bool $enabled=true;
    public bool $unavailable=false; public bool $mfaError=false; public bool $legacyMfa=false; public string $epoch; public string $revision;
    public function __construct(private Crypto $crypto) {
        $this->epoch=str_repeat('a',64);$this->revision=str_repeat('b',64);
        $id='11111111-1111-4111-8111-111111111111';
        $this->users=[$id=>['id'=>$id,'username'=>'staff','email'=>'staff@example.com','role'=>'admin','ucrmRole'=>'admin',
            'homeScreen'=>'/crm','totpAuthEnabled'=>false,'sessionTimeout'=>86400000,'keepMeSignedIn'=>false]];
    }
    private function error(string $code): string { return json_encode(['ok'=>false,'error'=>['code'=>$code]])."\n"; }
    public function exchange(string $frame): string {
        if ($this->unavailable) { throw new RuntimeException('Unavailable'); }
        $e=json_decode($frame,true);$signed=implode("\n",['UCRM-OIDC-ADAPTER-V2',$e['caller'],$e['keyId'],(string)$e['at'],$e['nonce'],$e['body']]);
        if (!hash_equals(hash_hmac('sha256',$signed,$this->crypto->transportKey()),$e['mac'])) { throw new RuntimeException('Bad transport'); }
        $b=json_decode(base64_decode(strtr($e['body'],'-_','+/')),true);$op=$b['operation'];
        if ($op==='status') {$r=['kind'=>'status','protocol'=>2,'enabled'=>$this->enabled,'pluginEnabled'=>true,'serverEpoch'=>$this->epoch,'configRevision'=>$this->revision,'nativeVersion'=>'2.4.220','sourceBundleSha256'=>str_repeat('c',64)];}
        elseif ($op==='resolve'||$op==='inspect') {
            if(!$this->enabled)return $this->error('OIDC_DISABLED');
            $users=array_values(array_filter($this->users,fn($u)=>$op==='resolve'?$u['email']===$b['email']:$u['id']===$b['nativeUserId']));
            if(count($users)!==1||($users[0]['disabled']??false))return $this->error('ADMISSION_DENIED');
            $r=['kind'=>'user','user'=>$users[0]];
        } elseif ($op==='issue') {
            ++$this->issues;$u=$this->users[$b['nativeUserId']];
            if($this->legacyMfa&&$u['totpAuthEnabled']){$id=uuid();$this->challenges[$id]=$u['id'];$r=['kind'=>'mfa','twoFactorToken'=>$id,'expiresAt'=>time()+300,'receipt'=>'test-receipt-'.$id,'user'=>$u];}
            else{$r=$this->pair($u);}
        } elseif($op==='complete-mfa'){
            if($this->mfaError)return $this->error('NATIVE_UNAVAILABLE');
            if($b['verificationCode']!=='123456')return $this->error('MFA_INVALID');
            if(!isset($this->challenges[$b['twoFactorToken']]))return $this->error('MFA_EXPIRED');
            unset($this->challenges[$b['twoFactorToken']]);$r=$this->pair($this->users[$b['nativeUserId']]);
        } elseif($op==='revoke'){unset($this->sessions[$b['artifact']],$this->challenges[$b['artifact']]);$r=['kind'=>'revoked'];}
        elseif($op==='describe-caller'){$r=['kind'=>'caller','nativeUserId'=>array_key_first($this->users)];}
        else{throw new RuntimeException('Unexpected native operation');}
        return json_encode(['ok'=>true,'result'=>$r])."\n";
    }
    private function pair(array $u):array{$id=uuid();$this->sessions[$id]=$u['id'];return ['kind'=>'session','token'=>uuid(),'ucrmSessionId'=>$id,'cookieTtlMs'=>null,'createdAt'=>time(),'receipt'=>'test-receipt-'.$id,'user'=>$u];}
}
function fixture(): array {
    $dir='/tmp/oidc-unit-'.Crypto::random();mkdir($dir,0700);file_put_contents($dir.'/key',Crypto::random());chmod($dir.'/key',0600);
    $crypto=new Crypto($dir.'/key');$store=new Store($crypto,$dir.'/state.sqlite');$provider=new Provider();$adapter=new Adapter($crypto);
    $native=new NativeSession($crypto,['exchange'=>$adapter->exchange(...)]);$oidc=new Oidc($store,fn()=>$provider);
    $app=new Application($store,$crypto,$native,$oidc);$admin=['nativeUserId'=>array_key_first($adapter->users),'sessionId'=>uuid(),'createdAt'=>time(),
        'source'=>'native-unattributed','isClient'=>false,'permissions'=>['system/plugins'=>'edit']];
    $settings=Config::DEFAULTS;$settings['issuer']='https://identity.example/oidc';$settings['clientId']='test-client';$settings['canonicalOrigin']='https://crm.example';
    $vm=$app->saveSettings($admin,$settings+['expectedProviderRevision'=>0]);
    $app->replaceSecret($admin,['expectedCredentialRevision'=>$vm['credentialRevision'],'clientSecret'=>'synthetic-test-secret']);
    return compact('dir','crypto','store','provider','adapter','native','oidc','app','admin');
}
function login(array $f,array $claims=[],array $userinfo=[],?string $browser=null,?array $preview=null,bool $fresh=false):array{
    $browser??=Crypto::random();$audit=['remoteAddress'=>'192.0.2.1','userAgent'=>'unit'];
    $start=$f['app']->start($browser,'/crm/',$audit,$preview,$fresh);parse_str(parse_url($start['authorizationUrl'],PHP_URL_QUERY),$q);
    $code=$f['provider']->register($q,$claims,$userinfo);return compact('browser','audit','start','q','code');
}
function callback(array $f,array $l):array{return $f['app']->callback($l['browser'],['code'=>$l['code'],'state'=>$l['q']['state']],$l['audit']);}

if (defined('UCRM_OIDC_FIXTURES_ONLY')) { return; }
try {
    $f=fixture();$crypto=$f['crypto'];$cipher=$crypto->seal(['secret'=>'synthetic'],'record:1');
    check('encryption round trip',$crypto->open($cipher,'record:1')['secret']==='synthetic');
    check('fresh encryption nonce',$cipher!==$crypto->seal(['secret'=>'synthetic'],'record:1'));
    denied('ciphertext cannot move between records',fn()=>$crypto->open($cipher,'record:2'),'STATE_UNAVAILABLE');
    file_put_contents($f['dir'].'/wrong',Crypto::random());$wrong=new Crypto($f['dir'].'/wrong');
    denied('wrong key refuses existing database',fn()=>new Store($wrong,$f['dir'].'/state.sqlite'),'KEY_MISMATCH');
    $again=new Store($crypto,$f['dir'].'/state.sqlite');check('WAL state survives reopening',$again->one('SELECT provider_revision FROM settings')['provider_revision']===1);
    check('credential ciphertext excludes plaintext',!str_contains($f['store']->one('SELECT secret_enc FROM settings')['secret_enc'],'synthetic-test-secret'));
    check('configuration excludes secret',!str_contains(json_encode($f['app']->configuration($f['admin'])),'synthetic-test-secret'));
    $csrf=$f['app']->csrf('browser','flow:start');$f['app']->checkCsrf('browser','flow:start',$csrf);
    denied('CSRF binds purpose',fn()=>$f['app']->checkCsrf('browser','admin',$csrf),'CSRF_DENIED');
    denied('CSRF binds session',fn()=>$f['app']->checkCsrf('another','flow:start',$csrf),'CSRF_DENIED');
    foreach(['https://evil.example','//evil.example','/crm/%6cogout','/crm/%5fplugins/ucrm-oidc/public.php','/crm/../nms/login','/crm/%252fanything','/nms/api/v2.1/user','/crm/evil%0a','/crm/\\evil'] as $url){denied('unsafe return '.$url,fn()=>Config::returnPath($url),'UNSAFE_RETURN_PATH');}
    check('normal native return retained',Config::returnPath('/crm/client/123?view=overview')==='/crm/client/123?view=overview');
    check('nested JSON pointer claim',Config::claim(['account'=>['email/verified'=>true]],'/account/email~1verified')===true);
    foreach(['127.1','2130706433','0x7f000001','0177.0.0.1','127.00.0.1'] as $host) {
        denied('noncanonical numeric host '.$host,fn()=>Config::url('https://'.$host.'/'),'INVALID_HTTPS_URL');
    }
    foreach(['127.0.0.1','::1','10.1.2.3','169.254.169.254','100.64.0.1','198.19.1.1','224.0.0.1','::ffff:127.0.0.1','2002:7f00:1::'] as $ip){check('unsafe provider address '.$ip,!HttpClient::publicAddress($ip));}
    check('public IPv4 accepted',HttpClient::publicAddress('8.8.8.8'));
    $started=hrtime(true);$addresses=HttpClient::resolveProcess([PHP_BINDIR.'/php','-n','-r','usleep(2000000);echo "[]";'],60);
    check('DNS child deadline enforced',$addresses===[]&&(hrtime(true)-$started)<1000000000);
    check('DNS child stderr overflow bounded',HttpClient::resolveProcess([PHP_BINDIR.'/php','-n','-r','fwrite(STDERR,str_repeat("x",10000));echo "[]";'])===[]);
    check('resolver works after timeout',HttpClient::resolveProcess([PHP_BINDIR.'/php','-n','-r','echo "[\"8.8.8.8\"]";'])===['8.8.8.8']);

    $l=login($f);check('authorization uses PKCE S256',$l['q']['code_challenge_method']==='S256'&&strlen($l['q']['code_challenge'])===43);
    denied('wrong browser does not consume state',fn()=>$f['app']->callback(Crypto::random(),['state'=>$l['q']['state'],'code'=>$l['code']],$l['audit']),'FLOW_INVALID');
    callback($f,$l);check('verified callback issues no native session',$f['adapter']->issues===0);
    denied('callback replay denied',fn()=>callback($f,$l),'FLOW_INVALID');
    $result=$f['app']->handoff($l['browser'],$l['start']['flowId'],$l['audit'],null);
    check('first verified email issues native session with native session-cookie policy',$result['kind']==='session'&&$result['cookieTtlMs']===null);
    check('binding persists before handoff',$f['store']->one('SELECT COUNT(*) AS n FROM bindings')['n']===1);
    check('issuance ledger persists before handoff',$f['store']->one('SELECT COUNT(*) AS n FROM sessions')['n']===1);
    denied('handoff replay never reissues',fn()=>$f['app']->handoff($l['browser'],$l['start']['flowId'],$l['audit'],null),'FLOW_USED');
    check('exactly one native issuance',$f['adapter']->issues===1);
    $l2=login($f,[],['email'=>'different@example.com','email_verified'=>false]);callback($f,$l2);
    check('bound subject survives email change',$f['app']->handoff($l2['browser'],$l2['start']['flowId'],$l2['audit'],null)['kind']==='session');
    $f['adapter']->users[array_key_first($f['adapter']->users)]['disabled']=true;
    $l3=login($f);denied('disabled bound user rechecked',fn()=>callback($f,$l3),'ADMISSION_DENIED');
    $f['adapter']->users[array_key_first($f['adapter']->users)]['disabled']=false;
    $vm=$f['app']->configuration($f['admin']);$f['app']->replaceSecret($f['admin'],['expectedCredentialRevision'=>$vm['credentialRevision'],'clientSecret'=>'']);
    check('blank secret preserves revision',$f['app']->configuration($f['admin'])['credentialRevision']===$vm['credentialRevision']);
    denied('stale settings revision rejected',fn()=>$f['app']->saveSettings($f['admin'],$vm['settings']+['expectedProviderRevision'=>0]),'REVISION_CONFLICT');
    $l4=login($f);$f['app']->replaceSecret($f['admin'],['expectedCredentialRevision'=>$vm['credentialRevision'],'clientSecret'=>'rotated-synthetic']);
    denied('credential change invalidates pending callback',fn()=>callback($f,$l4),'FLOW_CONFIGURATION_CHANGED');
    $old=$f['admin'];$old['createdAt']=time()-301;denied('old native session cannot edit',fn()=>$f['app']->clearSecret($old,['expectedCredentialRevision'=>3]),'RECENT_AUTH_REQUIRED');
    $untracked=$f['admin'];$untracked['source']='adapter';denied('unledgered adapter session cannot claim recent local auth',fn()=>$f['app']->assertFresh($untracked),'RECENT_AUTH_REQUIRED');

    foreach([
        ['missing nonce',['nonce'=>null],[]],['wrong nonce',['nonce'=>'wrong'],[]],['wrong issuer',['iss'=>'https://wrong.example'],[]],
        ['wrong audience',['aud'=>'other'],[]],['wrong azp',['azp'=>'other'],[]],['multiple audiences missing azp',['aud'=>['test-client','other']],[]],
        ['expired ID token',['exp'=>time()-60],[]],['future issued time',['iat'=>time()+90],[]],['future auth time',['auth_time'=>time()+90],[]],
        ['unverified first email',[],['email_verified'=>'true']],['missing first email',[],['email'=>null]],['unknown email',[],['email'=>'unknown@example.com']],
        ['userinfo subject mismatch',[],['sub'=>'other']],
    ] as [$name,$claims,$info]){$x=fixture();$a=login($x,$claims,$info);denied($name,fn()=>callback($x,$a));check($name.' creates no native pair',$x['adapter']->issues===0);}
    $x=fixture();$a=login($x,['aud'=>['test-client','other'],'azp'=>'test-client']);callback($x,$a);check('correct multiple audiences accepted',true);
    $x=fixture();$a=login($x);$x['provider']->tokenStatus=302;denied('redirect token response with valid signed body denied',fn()=>callback($x,$a));
    foreach (['none','HS256','RS512'] as $algorithm) {
        $x=fixture();$a=login($x);$x['provider']->codes[$a['code']]['headers']['alg']=$algorithm;
        denied('ID algorithm '.$algorithm.' cannot relax RS256 policy',fn()=>callback($x,$a));
    }
    $x=fixture();$a=login($x);$x['provider']->key=openssl_pkey_new(['private_key_bits'=>2048,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);
    denied('invalid real RSA signature denied',fn()=>callback($x,$a));
    $x=fixture();$a=login($x);callback($x,$a);
    check('first signed login caches one JWKS response',$x['provider']->jwksRequests===1);
    $rotated=new Provider();$rotated->jwks['keys'][0]['kid']='rotated-key';
    $x['provider']->key=$rotated->key;$x['provider']->jwks=$rotated->jwks;
    $a=login($x);$x['provider']->codes[$a['code']]['headers']['kid']='rotated-key';callback($x,$a);
    check('new signing key refreshes cached JWKS and validates real signature',$x['provider']->jwksRequests===2);
    $a=login($x);$x['provider']->codes[$a['code']]['headers']['kid']='rotated-key';callback($x,$a);
    check('rotated signing key is reused from validated cache',$x['provider']->jwksRequests===2);
    $a=login($x);$x['provider']->codes[$a['code']]['headers']['kid']='unpublished-key';
    denied('repeated unknown key cannot force another refresh inside limit',fn()=>callback($x,$a));
    check('unknown key cannot flood JWKS endpoint or issue native session',$x['provider']->jwksRequests===2&&$x['adapter']->issues===0);
    $x=fixture();$a=login($x);$x['provider']->codes[$a['code']]['headers']['kid']='unpublished-key';
    denied('unpublished signing key remains denied after one refresh',fn()=>callback($x,$a));
    check('unknown signing key performs at most one refresh',$x['provider']->jwksRequests===2&&$x['adapter']->issues===0);
    $x=fixture();$a=login($x);$x['provider']->codes[$a['code']]['query']['code_challenge']='wrong';
    denied('failed PKCE exchange consumes callback',fn()=>callback($x,$a));denied('failed callback cannot be retried',fn()=>callback($x,$a),'FLOW_INVALID');
    $x=fixture();$a=login($x,[],[],null,null,true);check('fresh login requests max_age0',(string)$a['q']['max_age']==='0');
    $x['provider']->codes[$a['code']]['claims']['auth_time']=time()-120;denied('fresh login rejects old provider authentication',fn()=>callback($x,$a));
    $x=fixture();$a=login($x,[],[],null,$x['admin']);callback($x,$a);$v=$x['app']->completion($a['browser'],$a['start']['flowId']);
    check('preview has no binding or ordinary native session',$v['kind']==='preview'&&$x['adapter']->issues===0&&$x['store']->one('SELECT COUNT(*) AS n FROM bindings')['n']===0);
    denied('preview cannot be issued',fn()=>$x['app']->handoff($a['browser'],$a['start']['flowId'],$a['audit'],null),'FLOW_USED');
    $x=fixture();$a=login($x);callback($x,$a);denied('other signed in identity prevents handoff',fn()=>$x['app']->handoff($a['browser'],$a['start']['flowId'],$a['audit'],['nativeUserId'=>uuid()]),'SIGN_OUT_OTHER_ACCOUNT');
    check('account mismatch produces no binding',$x['store']->one('SELECT COUNT(*) AS n FROM bindings')['n']===0);

    $x=fixture();$uid=array_key_first($x['adapter']->users);$x['adapter']->legacyMfa=true;$x['adapter']->users[$uid]['totpAuthEnabled']=true;$a=login($x);callback($x,$a);
    $m=$x['app']->handoff($a['browser'],$a['start']['flowId'],$a['audit'],null);check('MFA challenge stays server only',$m===['kind'=>'mfa']);
    denied('wrong native OTP fails',fn()=>$x['app']->completeMfa($a['browser'],$a['start']['flowId'],'000000',$a['audit'],null),'MFA_INVALID');
    check('MFA failure creates no session',$x['store']->one('SELECT COUNT(*) AS n FROM sessions')['n']===0);
    $m=$x['app']->completeMfa($a['browser'],$a['start']['flowId'],'123456',$a['audit'],null);check('native MFA success recorded before delivery',$m['kind']==='session'&&$x['store']->one('SELECT COUNT(*) AS n FROM sessions')['n']===1);
    $binding=$x['app']->records($x['admin'],'bindings',[])['items'][0];$x['app']->unlink($x['admin'],['bindingId'=>$binding['id'],'expectedVersion'=>$binding['version']]);
    check('unlink revokes issued native session',count($x['adapter']->sessions)===0);
    $a=login($x);denied('unlink tombstone prevents automatic relink',fn()=>callback($x,$a),'IDENTITY_UNLINKED');
    $x['app']->relink($x['admin'],['bindingId'=>$binding['id'],'nativeUserId'=>$uid,'expectedVersion'=>2]);
    $a=login($x);callback($x,$a);check('explicit relink restores controlled admission',true);

    $x=fixture();$s=$x['app']->configuration($x['admin'])['settings'];$x['oidc']->discovery($s);
    $x['provider']->metadata['token_endpoint_auth_methods_supported']=['client_secret_basic'];$x['store']->run('DELETE FROM cache');$x['oidc']->discovery($s);
    $s['clientAuthMethod']='client_secret_post';denied('cached discovery rechecks new authentication method',fn()=>$x['oidc']->discovery($s),'CLIENT_AUTH_UNSUPPORTED');
    $x=fixture();$s=$x['app']->configuration($x['admin'])['settings'];unset($x['provider']->metadata['userinfo_endpoint']);$s['emailSource']='id_token';$x['oidc']->discovery($s);$s['emailSource']='userinfo';
    denied('cached discovery rechecks UserInfo requirement',fn()=>$x['oidc']->discovery($s),'ENDPOINT_ORIGIN_DENIED');
    $x=fixture();$small=openssl_pkey_new(['private_key_bits'=>1024,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);$d=openssl_pkey_get_details($small);
    $x['provider']->jwks['keys'][0]['n']=b64(str_repeat("\0",128).$d['rsa']['n']);
    denied('padded weak RSA modulus rejected',fn()=>(new CachedJwks($x['store'],$x['provider'],'https://identity.example/jwks',time(...)))->getJwks(),'INVALID_JWKS');
    $x=fixture();$x['provider']->jwks['keys'][0]['dp']='private';denied('private RSA key material rejected',fn()=>(new CachedJwks($x['store'],$x['provider'],'https://identity.example/jwks',time(...)))->getJwks(),'INVALID_JWKS');
    echo json_encode(['php'=>PHP_VERSION,'passed'=>count($checks),'checks'=>$checks],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),"\n";
} catch(Throwable $e) { echo json_encode(['php'=>PHP_VERSION,'passed'=>count(array_filter($checks,fn($c)=>$c['passed'])),'failure'=>$e->getMessage(),'type'=>get_class($e),'checks'=>$checks],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),"\n";exit(1); }
