"""Read native service identities and write a new local deployment contract.

Docker calls are inspect/exec-read only. No native application is bootstrapped,
no service is restarted, and no account, data, key or permission is changed.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess

API_PROBE = r'''
const fs=require('fs'),crypto=require('crypto');
const files=['/home/app/unms/index.js','/home/app/unms/api.js'];
const hashes={};for(const f of files)if(fs.existsSync(f))hashes[f]=crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const processes=[];
for(const p of fs.readdirSync('/proc').filter(p=>/^[0-9]+$/.test(p))){
 if(+p===process.pid)continue;
 try{const args=fs.readFileSync('/proc/'+p+'/cmdline','utf8').split('\0');
 if(!args.some(a=>/^(?:\/home\/app\/unms\/)?(?:index|api)\.js$/.test(a)))continue;
 const status=fs.readFileSync('/proc/'+p+'/status','utf8');
 const ids=key=>{const match=status.match(new RegExp('^'+key+':\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)$','m'));if(!match)throw Error();return match.slice(1).map(Number);};
 processes.push({uid:ids('Uid'),gid:ids('Gid')});}catch(error){if(error.code!=='ENOENT')throw error;}
}
process.stdout.write(JSON.stringify({processes,hashes,uidMap:fs.readFileSync('/proc/self/uid_map','utf8').trim(),gidMap:fs.readFileSync('/proc/self/gid_map','utf8').trim()}));
'''
CRM_PROBE = r'''
$pools=[];
foreach(glob('/usr/local/etc/php-fpm.d/*.conf') as $path){
 $data=parse_ini_file($path,true,INI_SCANNER_RAW);if(!is_array($data))exit(2);
 foreach($data as $section=>$values)if(is_array($values))foreach(['user','group'] as $field)
 if(isset($values[$field]))$pools[$section][$field]=$values[$field];
}
$pool=$pools['www-plugins']??null;if(!is_array($pool)||!isset($pool['user'],$pool['group']))exit(3);
$user=ctype_digit($pool['user'])?posix_getpwuid((int)$pool['user']):posix_getpwnam($pool['user']);
$group=ctype_digit($pool['group'])?posix_getgrgid((int)$pool['group']):posix_getgrnam($pool['group']);
if(!$user||!$group)exit(4);$uid=$user['uid'];$gid=$group['gid'];$active=0;
foreach(glob('/proc/[0-9]*/cmdline') as $path){
 $cmd=@file_get_contents($path,false,null,0,4096);if(!$cmd||!str_starts_with($cmd,'php-fpm: pool www-plugins'))continue;
 $status=@file_get_contents(dirname($path).'/status');if(!$status)continue;
 if(!preg_match('/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m',$status,$u)
 ||!preg_match('/^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m',$status,$g))exit(5);
 if(array_unique(array_map('intval',array_slice($u,1)))!==[$uid]||array_unique(array_map('intval',array_slice($g,1)))!==[$gid])exit(6);
 $active++;
}
echo json_encode(['uid'=>$uid,'gid'=>$gid,'pool'=>'www-plugins','activeWorkersVerified'=>$active]);
'''


def identity(api, crm):
    processes = api.get('processes', [])
    if not processes:
        raise ValueError('No running native API process was found')
    observed = set()
    for process in processes:
        for key in ('uid', 'gid'):
            values = process.get(key)
            if not isinstance(values, list) or len(values) != 4 or len(set(values)) != 1:
                raise ValueError('Native process has ambiguous real/effective/saved identity')
        observed.add((process['uid'][0], process['gid'][0]))
    if len(observed) != 1:
        raise ValueError('Native API processes have different identities')
    uid, gid = observed.pop()
    result = {'version': 1, 'api': {'uid': uid, 'gid': gid},
              'crm': {'uid': crm.get('uid'), 'gid': crm.get('gid')}}
    for service in ('api', 'crm'):
        for number in result[service].values():
            if type(number) is not int or not 0 < number <= 2147483647:
                raise ValueError('A non-root native service UID and GID are required')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker-context', required=True)
    parser.add_argument('--api-container', required=True)
    parser.add_argument('--crm-container', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    for value in (args.docker_context, args.api_container, args.crm_container):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value):
            raise ValueError('Invalid Docker owner/context identifier')
    if args.api_container == args.crm_container:
        raise ValueError('Separate API and CRM owners are required')
    if args.output.exists() or args.output.with_suffix('.receipt.json').exists():
        raise ValueError('Use a fresh output path; existing identity contracts are never replaced')
    docker = ['docker', '--context', args.docker_context]

    def run(argv):
        result = subprocess.run(docker + argv, capture_output=True, timeout=45)
        if result.returncode:
            raise RuntimeError('Read-only Docker inspection failed; no identity contract written')
        return result.stdout

    def owner(name):
        item = json.loads(run(['inspect', name]))[0]
        if not item['State']['Running'] or item['HostConfig'].get('UsernsMode') not in ('', 'host'):
            raise ValueError('Running native owners without user namespace remapping are required')
        return {'id': item['Id'], 'imageId': item['Image'], 'startedAt': item['State']['StartedAt']}

    before = {key: owner(name) for key, name in [('api', args.api_container), ('crm', args.crm_container)]}
    api = json.loads(run(['exec', '--user', '0:0', before['api']['id'], 'node', '-e', API_PROBE]))
    for key in ('uidMap', 'gidMap'):
        if not re.fullmatch(r'0\s+0\s+4294967295', api.get(key, '')):
            raise ValueError('User namespace mapping needs separate resource-ownership qualification')
    crm = json.loads(run(['exec', '--user', '0:0', before['crm']['id'], 'php', '-d', 'display_errors=0', '-r', CRM_PROBE]))
    result = identity(api, crm)
    after = {key: owner(name) for key, name in [('api', args.api_container), ('crm', args.crm_container)]}
    if before != after:
        raise ValueError('Native owners changed during discovery; repeat the read-only inspection')
    data = (json.dumps(result, indent=2) + '\n').encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('xb') as file:
        file.write(data)
    receipt = {'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'owners': before, 'apiProcessCount': len(api['processes']),
               'apiBundleHashes': api['hashes'], 'crmPool': crm['pool'],
               'activePluginWorkersVerified': crm['activeWorkersVerified'],
               'identitySha256': hashlib.sha256(data).hexdigest(),
               'productionDataOrCredentialsRead': False, 'nativeMutationsPerformed': False}
    with args.output.with_suffix('.receipt.json').open('x', encoding='utf-8') as file:
        file.write(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'discovered': result, 'nativeOwnersUnchanged': True, 'nativeMutationsPerformed': False}))


if __name__ == '__main__':
    main()
