#!/usr/bin/env python3

from pathlib import Path
import pycparser
import argparse
import sys
import traceback
from pycparser.c_ast import Assignment, Constant, BinaryOp, Node, Decl, FuncCall, FuncDef, TernaryOp, If, ID, Return, StructRef, UnaryOp, TypeDecl, PtrDecl
from pycparser.plyparser import ParseError

def make_int_constant(value):
    return Constant(type='int', value=str(value))

def read_c_int(s):
    s = s.rstrip('L')
    if s[:2].lower() == '0x':
        return int(s[2:], 16)
    return int(s)

def is_id(node, expected_name):
    return isinstance(node, ID) and node.name == expected_name

def do_constant_folding(node):
    if not isinstance(node, Node):
        return node
    for name, c in node.children():
        new_c = do_constant_folding(c)
        if c != new_c:
            try:
                setattr(node, name, new_c)
            except Exception:
                # e.g. ParamList name="params[0]"
                pass

    if isinstance(node, BinaryOp):
        op, left, right = node.op, node.left, node.right
        if not isinstance(left, Constant) or left.type != 'int':
            return node
        if not isinstance(right, Constant) or right.type != 'int':
            return node
        left_value = read_c_int(left.value)
        right_value = read_c_int(right.value)
        if op == '<<':
            return make_int_constant(left_value << right_value)
        elif op == '|':
            return make_int_constant(left_value | right_value)
        elif op == '&':
            return make_int_constant(left_value & right_value)
        elif op == '^':
            return make_int_constant(left_value ^ right_value)
        elif op == '-':
            return make_int_constant(left_value - right_value)
        elif op == '+':
            return make_int_constant(left_value + right_value)
    elif isinstance(node, TernaryOp):
        if isinstance(node.cond, Constant) and node.cond.type == 'int':
            if read_c_int(node.cond.value) != 0:
                return node.iftrue
            else:
                return node.iffalse
    elif isinstance(node, FuncCall):
        # just pick a side if this is using the zval_gc_flags macro
        # used in combination with TernaryOp
        if is_id(node.name, 'zval_gc_flags'):
            return make_int_constant(0)
    return node

# Notes about C:
#define IS_UNDEF					0
#define IS_NULL						1
#define IS_FALSE					2
#define IS_TRUE						3
#define IS_LONG						4
#define IS_DOUBLE					5
#define IS_STRING					6
#define IS_ARRAY					7
#define IS_OBJECT					8
#define IS_RESOURCE					9
#define IS_REFERENCE				10
IS_NULL = 1
IS_FALSE = 2


class Walker:
    def __init__(self):
        # Weak heuristic.
        # If there are no types in self.types, assume that the function returns void (and combine that with types_in_conditionals)
        self.types = set()
        self.types_in_conditionals = set()
        # This is the set of variables that probably alias return_value
        self.locals = set()
        self.conditional_depth = 0
    def walk(self, node):
        if not isinstance(node, Node):
            # print("skipping", type(node))
            return

        is_conditional = isinstance(node, If)
        if is_conditional:
            self.conditional_depth += 1
        
        # print("walking", type(node))
        old_locals = self.locals
        for c in node:
            self.walk(c)

        if is_conditional:
            self.conditional_depth -= 1
            
        self.locals = old_locals

        if isinstance(node, Decl):
            if is_id(node.init, 'return_value'):
                # print("Checking Decl {0}".format(repr(node)))
                node_type = node.type
                if isinstance(node_type, PtrDecl):
                    # e.g. process zval * __z = return_value
                    node_type = node_type.type
                if isinstance(node_type, TypeDecl) and isinstance(node_type.declname, str):
                    print("Adding " + node_type.declname + " to locals")
                    self.locals = self.locals | {node_type.declname}
            print("In walker.walk for Decl")
            # node.show()
        elif isinstance(node, Assignment):
            run_if_debug(lambda: print("Processing an Assignment. locals: {0}".format(str(self.locals))))
            run_if_debug(lambda: node.show())
            if node.op == '=' and self.is_return_value_type(node.lvalue):
                print("This is assigning to the return value")
                self.record_type(node.rvalue)
        elif isinstance(node, Return):
            if len(self.types) == 0 and len(self.types_in_conditionals) == 0:
                # This is returning without setting a possible type
                self.types_in_conditionals.add(IS_NULL)
        

    def is_return_value_type(self, node):
        # print("Checking if " + repr(node) + " is assigning to return value")
        if not isinstance(node, StructRef):
            return False
        if not is_id(node.field, 'type_info'):
            return False
        name = node.name
        # print("Checking name= " + repr(name))
        if not isinstance(name, StructRef):
            return False
        if not is_id(name.field, 'u1'):
            return False
        outer_name = name.name
        # print("Checking outer_name= " + repr(name))
        if isinstance(outer_name, UnaryOp):
            outer_name = outer_name.expr
        if not isinstance(outer_name, ID):
            return False
        return self.is_return_value_name(outer_name.name)

    def is_return_value_name(self, name):
        return name == 'return_value' or name in self.locals

    def record_type(self, rvalue):
        # XXX handle TernaryOp
        if isinstance(rvalue, Constant) and rvalue.type == 'int':
            rvalue = read_c_int(rvalue.value)
        if isinstance(rvalue, TernaryOp):
            # Handle assignments with ternaries, such as RETURN_BOOL (expr ? iftrue : iffalse)
            self.record_type(rvalue.iftrue)
            self.record_type(rvalue.iffalse)
            return
        if not isinstance(rvalue, int):
            print("Saw non-int " + repr(rvalue))
            rvalue = -1
        if self.conditional_depth > 0:
            self.types_in_conditionals.add(rvalue)
            return
        
        self.types.add(rvalue)
    def get_return_types(self):
        return_type_set = set(self.types_in_conditionals)
        if len(self.types) > 0:
            return_type_set |= self.types
        else:
            return_type_set.add(IS_NULL)
        return list(return_type_set)

DEBUG = False
def run_if_debug(fn):
    if DEBUG:
        fn()

def extract_function_signatures(filename: str):
    stmt_list = pycparser.parse_file(filename)
    if len(stmt_list.children()) == 0:
        raise Exception("Failed to load " + filename)
    for top_level_stmt in stmt_list:
        if not isinstance(top_level_stmt, FuncDef):
            continue
        name = top_level_stmt.decl.name
        if 'zif_' not in name:
            continue
        print("\n" + "=" * 80 + "\n" + name + "\n" + "=" * 80, flush=True)
        do_constant_folding(top_level_stmt)
        run_if_debug(lambda: top_level_stmt.show())
        w = Walker()
        w.walk(top_level_stmt)
        print("Inferred return types for {0}: {1}".format(name[4:], str(w.get_return_types())), flush=True)
        # top_level_stmt.show()

def process_file(filename):
    try:
        print("Processing " + str(filename), flush=True)
        extract_function_signatures(filename)
        print("Successfully processed " + str(filename), flush=True)
    except Exception as e:
        print("Failed to parse " + str(filename))
        print(repr(e))
        if not isinstance(e, ParseError):
            traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(prog='check_asts')
    parser.add_argument('--dir', nargs='+', help='list of directories')
    parser.add_argument('--file', nargs='+', help='list of files')
    args = parser.parse_args()
    print("Args: ", args)
    '''
    if args.dir is None and args.file is None:
        parser.print_help()
        sys.exit(1)
    '''
    
    # TODO: Add --dir or --file flags
    if args.file is not None:
        file = args.file
        if isinstance(file, str):
            file = [file]
        filenames = file
    else:
        filenames = list(Path('../php-src').glob('**/*.normalized_c'))
        
    for filename in filenames:
        process_file(filename)

    print("Found {0} filenames in ../php-src/**/*.normalized_c".format(len(filenames)))

if __name__ == '__main__':
    main()
