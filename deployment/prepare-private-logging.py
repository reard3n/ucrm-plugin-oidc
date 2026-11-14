"""Generate reviewed native logging overrides from exact supported input bytes.

Preparation only: no Docker calls, service edits, reloads, or secret inputs.
Mount generated files read-only through the existing operator service owner.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

HASHES = {
    'proxy_locations': 'a5cf79c431e7c3cb3924b0c5336a1307d33dd167abc9c829676406755220c547',
    'crm_http': '540bcdd72d0e4e842db9596a398d3b8318b0f967ddfb9005b6d4be10dcbfd3ed',
    'crm_server': '0c0b4442a91f5367096cec4cc7a59181475eedb993eb4d4caa4c0d6fadee2785',
    'fpm_pools': '04ba531b39974d536336d7375ee42dafd7c8dd62f15b8a69baf52db6e04851e1',
    'proxy_common_headers': ['b8c85200418bbaabf2b601f5ef6e0dfb1623293b7ee2cd33a36706280446569f',
        '8e4d987ff282f9082d0166ae945e625f406cf20b8e356afbeaf70ccba48c009e'],
    'proxy_plugin_headers': 'fa5f1188705c7cbbcf33e6b88bc88a2ec59b859c98c66dbd126a1da3eb6d169d',
    'proxy_main_template': ['90013315778911acb8ee1cd5b5e305406e32a037dae51eacb5124ae07a026a7e',
        '34cd6efb17040f0400d45c9b5bc0988bae0e6506e5e35112a545b83230efd5ae'],
}
ENTRY = '/crm/_plugins/ucrm-oidc/public.php'
ALIAS = '/_plugins/ucrm-oidc/public.php'
FPM = '''; Loaded after native zz-docker.conf. Native pool ownership/settings remain.
[www-plugins]
access.format = "%t %m %r %s %d"
php_admin_flag[display_errors] = off
php_admin_flag[display_startup_errors] = off
php_admin_value[zend.exception_ignore_args] = 1
'''
POLICY_MAP = '''
  # Only the trusted plugin response can opt clean form pages into same-origin.
  # Commas, unknown values and absent headers remain no-referrer.
  map $upstream_http_referrer_policy $ucrm_oidc_referrer {
    default no-referrer;
    ~^same-origin$ same-origin;
    ~^no-referrer$ no-referrer;
  }
'''


def one(text, old, new):
    if text.count(old) != 1: raise ValueError('native_anchor_changed')
    return text.replace(old, new, 1)


def add_policy_map(text):
    return one(text,'access_log off;','access_log off;\n'+POLICY_MAP)


def native_block(text, header):
    start = text.find(header)
    if start < 0 or text.count(header) != 1: raise ValueError('native_location_changed')
    opening = text.index('{',start); depth=1; end=opening+1
    while end < len(text) and depth:
        depth += (text[end] == '{') - (text[end] == '}'); end += 1
    if depth: raise ValueError('native_location_unclosed')
    return text[start:end]


def transform(inputs):
    for key, expected in HASHES.items():
        allowed=expected if isinstance(expected,list) else [expected]
        if hashlib.sha256(inputs[key]).hexdigest() not in allowed: raise ValueError('unsupported_native_logging_hash_' + key)
    source = {key:value.decode('utf-8') for key,value in inputs.items()}
    common=one(source['proxy_common_headers'],'add_header Referrer-Policy same-origin;',
        'add_header Referrer-Policy no-referrer always;')
    protected_headers=one(source['proxy_plugin_headers'],'include "snippets/headers/common-headers.conf";',common)
    response_headers=one(protected_headers,'add_header Referrer-Policy no-referrer always;',
        'add_header Referrer-Policy $ucrm_oidc_referrer always;')
    proxy_blocks=[]
    for public_path, original_path in [(ENTRY,'/crm/_plugins/'),(ALIAS,'/_plugins/')]:
        header='location '+original_path+' {'; original=native_block(source['proxy_locations'],header)
        clone=one(original,header,'location = '+public_path+' {\n  access_log off;\n  error_log /dev/null;')
        clone=one(clone,'include "snippets/ucrm-errors.conf";',
            'error_page 404 = @ucrm_oidc_private_404;\n  error_page 502 = @ucrm_oidc_private_502;')
        clone=one(clone,'include "snippets/headers/ucrm-headers-plugins.conf";',
            'proxy_hide_header Referrer-Policy;\nproxy_hide_header Cache-Control;\n'
            'add_header Cache-Control no-store always;\n'+response_headers)
        proxy_blocks += [clone, 'location ^~ '+public_path+' {\n  access_log off;\n  error_log /dev/null;\n'
            +protected_headers+'\n  add_header Cache-Control no-store always;\n'
            '  error_page 404 = @ucrm_oidc_private_404;\n  return 404;\n}']
    for status in [404,502]:
        proxy_blocks.append('location @ucrm_oidc_private_'+str(status)+' {\n  access_log off;\n  error_log /dev/null;\n'
            +protected_headers+'\n  add_header Cache-Control no-store always;\n'
            '  default_type text/plain;\n  return '+str(status)+' "Sign-in unavailable.\\n";\n}')
    proxy='\n\n'.join(proxy_blocks)+'\n\n'+source['proxy_locations']
    crm_header=r'location ~ ^/crm/_plugins/([a-z0-9-_]+)/public\.php(/|$) {'
    original=native_block(source['crm_server'],crm_header)
    clone=one(original,crm_header,'location = '+ENTRY+' {\n        access_log off;\n        error_log /dev/null;')
    clone=one(clone,'try_files $uri /app.php$is_args$args;','try_files $uri =404;')
    # Valid entry is exact; malformed/path-info suffixes cannot escape into the
    # generic plugin or Symfony logger. This does not change another plugin.
    denied='location ^~ '+ENTRY+' {\n        access_log off;\n        error_log /dev/null;\n        return 404;\n    }'
    crm=one(source['crm_server'],crm_header,clone+'\n\n    '+denied+'\n\n    '+crm_header)
    crm=one(crm,'access_log /data/log/ucrm/nginx/ucrm_access.log;',
        'access_log /data/log/ucrm/nginx/ucrm_access.log ucrm_oidc_safe;')
    http=one(source['crm_http'],'    include       mime.types;',
        '    include       mime.types;\n    # Query/header/body-free native diagnostics.\n'
        '    log_format ucrm_oidc_safe \'$time_iso8601 "$request_method $uri $server_protocol" $status $body_bytes_sent $request_time\';')
    # FPM's official %r is the path without query; no %Q/%q, headers, body,
    # environment or auth fields are permitted. Only the native plugin pool.
    return {'proxy-ucrm-locations.conf':proxy.encode(),'proxy-nginx.conf.template':add_policy_map(source['proxy_main_template']).encode(),'crm-nginx.conf':http.encode(),
        'crm-server.conf':crm.encode(),'zzz-ucrm-oidc-privacy.conf':FPM.encode()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in HASHES: parser.add_argument('--'+name.replace('_','-'),type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    inputs={key:getattr(args,key).read_bytes() for key in HASHES};outputs=transform(inputs)
    root=args.output.resolve()
    if root.exists(): raise ValueError('new_output_directory_required')
    root.mkdir(parents=True)
    for name,data in outputs.items(): (root/name).write_bytes(data)
    result={'schemaVersion':1,'supportedProfiles':['uisp-2.4.220-crm-4.4.33-php8.2-bridge','uisp-3.1.73-crm-4.6.20'],
        'sourceSha256':{key:hashlib.sha256(data).hexdigest() for key,data in inputs.items()},
        'outputSha256':{name:hashlib.sha256(data).hexdigest() for name,data in outputs.items()},
        'generatorSha256':hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n',b'\n')).hexdigest(),
        'destinations':{'proxy-ucrm-locations.conf':'proxy:/usr/local/openresty/nginx/templates/snippets/ucrm-locations.conf',
            'proxy-nginx.conf.template':'proxy:/usr/local/openresty/nginx/templates/nginx.conf.template',
            'crm-nginx.conf':'ucrm:/etc/nginx/nginx.conf','crm-server.conf':'ucrm:/etc/nginx/available-servers/ucrm.conf',
            'zzz-ucrm-oidc-privacy.conf':'ucrm:/usr/local/etc/php-fpm.d/zzz-ucrm-oidc-privacy.conf'},
        'runtimeValidated':False,'logMarkerAcceptance':False,'productionActivated':False}
    (root/'logging-receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'prepared':True,'output':str(root),'files':list(outputs),'runtimeAcceptancePending':True}))


if __name__=='__main__':main()
