<?php
declare(strict_types=1);
namespace UcrmOidc;

/** Deliberately excludes vendor responses, credentials and exception chains. */
final class AppException extends \RuntimeException
{
    public function __construct(public readonly string $safeCode, public readonly int $httpStatus = 400)
    {
        parent::__construct($safeCode);
    }
}
