"""
GraphQL Mutation Analyzer using official parser for robust detection.
Replaces fragile regex-based approach with AST parsing to accurately identify mutations.
"""

import logging
from typing import Set

from graphql import parse, OperationDefinitionNode, FieldNode
from graphql.language.ast import DocumentNode

logger = logging.getLogger(__name__)


class GraphQLMutationAnalyzer:
    """
    Robust GraphQL mutation detection using official parser.
    Replaces fragile regex approach.
    """

    @staticmethod
    def extract_mutation_names(query: str) -> Set[str]:
        """
        Extract ALL mutation field names from a GraphQL query.
        Returns empty set if query is invalid or has no mutations.

        Examples:
            >>> extract_mutation_names("mutation { launchRun deleteRun }")
            {'launchRun', 'deleteRun'}
        """
        try:
            ast = parse(query)
            return GraphQLMutationAnalyzer._find_mutations_in_ast(ast)
        except Exception as e:
            logger.warning(f"Failed to parse GraphQL query: {e}")
            if "mutation" in query.lower():
                return {"unknown_mutation"}
            return set()

    @staticmethod
    def _find_mutations_in_ast(ast: DocumentNode) -> Set[str]:
        """Walk AST and collect all mutation field names."""
        mutations = set()

        for definition in ast.definitions:
            if not isinstance(definition, OperationDefinitionNode):
                continue

            if definition.operation.value != "mutation":
                continue

            # Extract top-level mutation fields
            for selection in definition.selection_set.selections:
                if isinstance(selection, FieldNode):
                    mutations.add(selection.name.value)

        return mutations

    @staticmethod
    def is_mutation(query: str) -> bool:
        """Quick check if query contains any mutations."""
        return len(GraphQLMutationAnalyzer.extract_mutation_names(query)) > 0
