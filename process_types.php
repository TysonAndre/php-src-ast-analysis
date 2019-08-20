#!/usr/bin/env php
<?php

use Phan\Language\UnionType;

if ($argc !== 2) {
    echo "Usage: $argv[0] types.txt\n\n";
    echo "  Accepts a file containing 'Inferred return types for fn_name: [i1, i2, i3]\n";
    exit(1);
}
$file = $argv[1];
if (!is_readable($file)) {
    echo "Could not read $file\n";
    exit(1);
}
$contents = file_get_contents($file);
if (!is_string($contents)) {
    echo "file_get_contents failed for $file\n";
    exit(1);
}
const ZVAL_LOOKUP = [
    'IS_UNDEF',  // 0,
    'IS_NULL',  // 1,
    'IS_FALSE',  // 2,
    'IS_TRUE',  // 3,
    'IS_LONG',  // 4,
    'IS_DOUBLE',  // 5,
    'IS_STRING',  // 6,
    'IS_ARRAY',  // 7,
    'IS_OBJECT',  // 8,
    'IS_RESOURCE',  // 9,
    // 'IS_REFERENCE', // 10,
];
const UNION_TYPE_LOOKUP = [
    'undefined',  // 0,
    'null',  // 1,
    'false',  // 2,
    'true',  // 3,
    'int',  // 4,
    'float',  // 5,
    'string',  // 6,
    'array',  // 7,
    'object',  // 8,
    'resource',  // 9,
    // 'IS_REFERENCE', // 10,
    128 => 'probably-null',  // 128,
];
function infer_type(string $function, string $values) : string {
    $parts = array_map('intval', array_map('trim', explode(',', $values)));
    $zval_type_set = [];
    foreach ($parts as $part) {
        if ($part <= 0) {
            // -1 is when it couldn't be inferred.
            fwrite(STDERR, "$function had uninferrable zval type\n");
            return 'mixed';
        }
        $zval_type_set[$part % 256] = true;
    }
    $type_strings = [];
    if (isset($zval_type_set[2]) && isset($zval_type_set[3])) {
        $type_strings[] = 'bool';
        unset($zval_type_set[2], $zval_type_set[3]);
    }
    foreach ($zval_type_set as $i => $_) {
        $type_string = UNION_TYPE_LOOKUP[$i] ?? null;
        if (!$type_string) {
            fwrite(STDERR, "$function had unknown zval type $i\n");
            return 'mixed';
        }
        $type_strings[] = $type_string;
    }
    sort($type_strings);
    return implode('|', $type_strings);
}

function infer_types(string $raw_log_contents) : array {
    $types = [];
    foreach (explode("\n", $raw_log_contents) as $line) {
        $line = trim($line);
        if (!preg_match('/Inferred return types for ([a-zA-Z_0-9:]+): \[([^\[\]]*)\]/', $line, $matches)) {
            continue;
        }
        [$_, $function, $values] = $matches;
        $union_type = infer_type($function, $values);
        $types[$function] = $union_type;
    }
    ksort($types);
    return $types;
}
$types = infer_types($contents);
foreach ($types as $function => $union_type) {
    echo "$function: $union_type\n";
}


function compare_function_type(string $function, string $extracted_type, array $signatures_from_elsewhere) {
    if (array_key_exists($function, $signatures_from_elsewhere)) {
        $union_type_from_elsewhere = UnionType::fromFullyQualifiedString($signatures_from_elsewhere[$function]);
        foreach (explode('|', $extracted_type) as $type_part) {
            if ($type_part === 'probably-null') {
                return;
            }
            $type = UnionType::fromFullyQualifiedString($type_part);
            if (!$type->canCastToUnionType($union_type_from_elsewhere)) {
                echo "$function: Could not cast $type of $extracted_type to $union_type_from_elsewhere\n";
            }
        }
        return;
    }
    echo "Missing function $function: $extracted_type\n";
}

// signatures_from_elsewhere was inferred from opcache for php 8. This will likely change.
function compare_types(array $types, array $signatures_from_elsewhere) {
    foreach ($types as $function => $type) {
        compare_function_type($function, $type, $signatures_from_elsewhere);
    }
}
$phan_signature_map_path = '../phan/src/Phan/Language/Internal/FunctionSignatureMapReal.php';
if (is_readable($phan_signature_map_path)) {
    require_once '../phan/src/Phan/Bootstrap.php';
    $phan_signature_map = require($phan_signature_map_path);
    // echo json_encode(array_slice(array_keys($phan_signature_map), 0, 20)) . "\n";
    compare_types($types, $phan_signature_map);
} else {
    echo "Could not find $phan_signature_map_path to compare\n";
}
