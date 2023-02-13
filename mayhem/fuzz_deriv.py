#! /usr/bin/env python3
import ast
import types
import atheris
import inspect
import sys
import os
import random
import fuzz_helpers
import tempfile
from typing import Callable, Optional
from importlib.util import module_from_spec, spec_from_loader

with atheris.instrument_imports(include=['tangent']):
    import tangent


# Generate the default source code for fuzzing
def f(x):
    a = x * x
    b = x / a
    c = a + b
    d = a - c
    return d
def_src = bytes(inspect.getsource(f), 'utf-8')

class ShowSourceLoader:
    def __init__(self, modname: str, source: str) -> None:
        self.modname = modname
        self.source = source

    def get_source(self, modname: str) -> str:
        if modname != self.modname:
            raise ImportError(modname)
        return self.source

def to_func(data: str) -> Callable:
    fname = tempfile.mktemp(suffix='.py')
    modname = os.path.splitext(os.path.basename(fname))[0]
    assert modname not in sys.modules
    loader = ShowSourceLoader(modname, data)
    spec = spec_from_loader(modname, loader, origin=fname)
    mod = module_from_spec(spec)
    co = compile(data, mode='exec', filename=fname)
    exec(co, mod.__dict__)
    sys.modules[modname] = mod
    return mod.f

@atheris.instrument_func
def build_function(fdp: fuzz_helpers.EnhancedFuzzedDataProvider) -> Optional[Callable]:
    try:
        func_def_code = fdp.ConsumeRemainingBytes().decode('utf-8')
        return to_func(func_def_code)
    except Exception as e:
        return None

value_matchers = ['chained', 'exactly one']
def CustomMutator(data, max_size, seed):
    try:
        inspect.getsource(to_func(data.decode('utf-8')))
        func_src = data
    except Exception:
        func_src = def_src
    else:
        func_src = atheris.Mutate(func_src, len(func_src))
    return func_src

@atheris.instrument_func
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        if grad_func := build_function(fdp):
            tangent.grad(grad_func)(5)
        else:
            return -1
    except (tangent.TangentParseError, AttributeError, SyntaxError):
        return -1
    except (TypeError, IndexError):
        if random.random() > 0.999:
            raise
        return 0
    except ValueError as e:
        if any(x in str(e) for x in value_matchers):
            return -1
        raise e




def main():
    atheris.Setup(sys.argv, TestOneInput, custom_mutator=CustomMutator)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
