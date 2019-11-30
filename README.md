php-src-analysis
================

A collection of scripts for analyzing the C ASTs of functions of php-src.
This focuses on determining the real types of parameters/return values of internal functions and methods,
when this information is not available in reflection.

Dependencies
------------

- php-src forked to change macros and headers to be easier to parse: https://github.com/TysonAndre/php-src/tree/parsing-patches
- https://github.com/TysonAndre/pycparser (with a few additional header definitions)
- gcc

Running
-------

1. Run `./check.sh ../php-src ../php-src/ext` to generate normalized ASTs against php-src.
   https://github.com/TysonAndre/php-src/tree/parsing-patches may be used.
   (It removes dependencies on C header files and annotations that pycparser won't parse (and has no intentions of parsing) (e.g. gcc-specific annotations)

   This will fail on a few files. Editing those files, adding include paths to check.sh, or adding files to `fake_libc_include_extra` will help fix that.
2. Run `./check_asts.py [--file path/to/individual_file1.c.c_normalized] | tee analysis_results_php80.txt` (requires patches from https://github.com/eliben/pycparser/pull/344 to parse one file in date libraries to to regex backtracking)

   By default, this runs on ../php-src.
3. Run `php process_types.php` to generate union types that **could be inferred** from php-src (or the extension in question).
   This is not guaranteed to be correct, but may be useful in discovering incorrectly documented/typed code.

   - See `example_php80_types.txt` for an example of the inferred types and it showing the types that were missing from another array.
     TODO: Print contradiction in types, mentioning that null is often error-prone.

   Note that this does not make any attempt to analyze helper methods that set return types.

   If the union type outputted by `process_types` contains `null`, then it's likely to be incorrect.

   - TODO: Distinguish between absence of a return statement and an explicit return such as a `RETURN_NULL;` macro, when possible.
   - TODO: Check for constructs that throw exceptions and don't infer union types for those in `check_asts.py`

   If `../phan/src/Phan/Language/Internal/FunctionSignatureMapReal.php` exists, this will print the union types which were missing from it. (Signatures containing `null` are likely to be incorrect.)

   - See `example_missing_php80_signatures.txt` for an example

Planned tasks:

- Infer the types of parameters from `zend_parse_parameters` and the fast parameter parsing API.
- Handle the difference in return type caused by php 8 throwing and 7 (usually) not throwing for invalid parameter types.
