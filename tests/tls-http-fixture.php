<?php
declare(strict_types=1);
// Loopback-only synthetic HTTP faults. No production/provider credentials.
$directory = $argv[1];
$context = stream_context_create(['ssl' => ['local_cert' => $directory . '/server.pem', 'local_pk' => $directory . '/server-key.pem']]);
$server = stream_socket_server('tls://127.0.0.1:19447', $errno, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
if ($server === false) { exit(2); }
echo "ready\n"; flush();
while ($socket = @stream_socket_accept($server, 30)) {
    stream_set_timeout($socket, 3);
    $line = fgets($socket, 4096);
    $path = explode(' ', $line ?: '')[1] ?? '/';
    $length = 0; $count = 0;
    while (($line = fgets($socket, 4096)) !== false && trim($line) !== '') {
        if (++$count > 32) { break; }
        if (stripos($line, 'Content-Length:') === 0) { $length = (int) trim(substr($line, 15)); }
    }
    if ($length > 0 && $length <= 16384) { fread($socket, $length); }
    if ($path === '/slow') { usleep(14000000); }
    $status = $path === '/redirect' ? '302 Found' : '200 OK';
    $body = $path === '/large' ? str_repeat('x', 131073) : '{"ok":true}';
    $extra = $path === '/redirect' ? "Location: https://unapproved.example/secret\r\n" : '';
    if ($path === '/headers') { $extra .= 'X-Large: ' . str_repeat('x', 17000) . "\r\n"; }
    @fwrite($socket, "HTTP/1.1 $status\r\nContent-Type: application/json\r\nConnection: close\r\n" . $extra . 'Content-Length: ' . strlen($body) . "\r\n\r\n" . $body);
    fclose($socket);
}
