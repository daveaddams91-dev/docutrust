from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class CompileMixin:

    def compile_zk_dsl(
        self,
        expression: str
    ) -> Dict[str, Any]:
        """Compiles a declarative predicate expression into an AST & constraint system."""
        from .zk_dsl import ZKDSLEngine
        return ZKDSLEngine.compile_dsl(expression)
