<?php
declare(strict_types=1);
$files = [];
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__ . '/../plugin', FilesystemIterator::SKIP_DOTS));
foreach ($iterator as $file) {
    if ($file->getExtension() === 'php' && !str_contains($file->getPathname(), '/vendor/')) { $files[] = $file->getPathname(); }
}
foreach ($files as $file) {
    $process = proc_open([PHP_BINDIR . '/php', '-l', $file], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    fclose($pipes[0]); $output = stream_get_contents($pipes[1]); $error = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    if (proc_close($process) !== 0) { echo $output, $error; exit(1); }
}
echo json_encode(['php' => PHP_VERSION, 'lintedFiles' => count($files), 'passed' => true]), "\n";
