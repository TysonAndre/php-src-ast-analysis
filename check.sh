#!/usr/bin/env bash
function usage() {
    echo "Usage: $0 path/to/php-src path/to/extension-folder" 1>&2
    echo "Runs files containing PHP_FUNCTION (aka ZEND_FUNCTION) through the C preprocessor, so that the source can be statically analyzed for a good guess at real function/return types" 1>&2
    exit 1
}
if [[ $# != 2 ]]; then
    usage
fi
PHP_SRC_DIR="$1"
EXTENSION_DIR="$2"
if [[ ! -d "$PHP_SRC_DIR/ext/standard" ]]; then
    echo "'$PHP_SRC_DIR' is not the path to an source checkout of php-src" 1>&2
    usage
fi
if [[ ! -d "$EXTENSION_DIR" ]]; then
    echo "Could not find extension directory '$EXTENSION_DIR" 1>&2
    usage
fi
if [[ ! -d "pycparser/utils/fake_libc_include" ]]; then
    echo "Failed to find pycparser/utils/fake_libc_include - download it" 1>&2
    usage
fi

for file in $(find "$EXTENSION_DIR" -iname '*.c' -print0 | xargs -0 grep -RE '(PHP|ZEND)_(FUNCTION|METHOD)' -l ); do
    BASE_DIR=$(dirname "$file")
    echo "Processing $file"
    gcc -nostdinc -D__inline= -D'__attribute__(x)=' -E "$file" \
        -I pycparser/utils/fake_libc_include \
        -I fake_libc_include_extra \
        -I "$PHP_SRC_DIR/Zend" \
        -I "$PHP_SRC_DIR/main" \
        -I "$PHP_SRC_DIR" \
        -I "$PHP_SRC_DIR/TSRM" \
        -I "$PHP_SRC_DIR/ext/intl" \
        -I "$BASE_DIR"  \
        > "$file.normalized_c"
done
