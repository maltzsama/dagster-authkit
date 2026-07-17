"""
GraphQL Mutation Analyzer using official parser for robust detection.
Replaces fragile regex-based approach with AST parsing to accurately identify mutations.
"""

import logging
from typing import Optional, Set

from graphql import (
    parse,
    OperationDefinitionNode,
    FieldNode,
    FragmentSpreadNode,
    InlineFragmentNode,
)
from graphql.language.ast import DocumentNode, FragmentDefinitionNode

logger = logging.getLogger(__name__)

# Sentinel value to flag unparseable queries in the mutation set.
# This is checked by the middleware to reject malformed requests before they
# reach the GraphQL engine, preventing potential RBAC bypass via parser confusion.
_SENTINEL_UNPARSEABLE = "__UNPARSEABLE_QUERY__"


class GraphQLMutationAnalyzer:
    """
    Robust GraphQL mutation detection using official parser.
    Replaces fragile regex approach.
    """

    @staticmethod
    def extract_mutation_names(query: str, operation_name: Optional[str] = None) -> Set[str]:
        """
        Extract ALL mutation field names from a GraphQL query.
        Returns sentinel set with __UNPARSEABLE_QUERY__ if query is invalid.
        Returns empty set if query has no mutations.

        If operation_name is provided, only the named operation is analyzed.
        This prevents false-positive RBAC blocks when a document contains
        both query and mutation operations but only the query is executed.

        Examples:
            >>> extract_mutation_names("mutation { launchRun deleteRun }")
            {'launchRun', 'deleteRun'}
            >>> extract_mutation_names("query GetRuns { ... } mutation DoStuff { launchRun }",
            ...                        operation_name="GetRuns")
            set()
        """
        try:
            ast = parse(query)
            return GraphQLMutationAnalyzer._find_mutations_in_ast(ast, operation_name)
        except Exception as e:
            logger.warning(f"Failed to parse GraphQL query: {e}")
            return {_SENTINEL_UNPARSEABLE}

    @staticmethod
    def is_parseable(query: str) -> bool:
        """
        Check if a GraphQL query can be successfully parsed.

        Returns:
            True if the query is valid GraphQL syntax, False otherwise.
        """
        if not query or not query.strip():
            return False
        try:
            parse(query)
            return True
        except Exception:
            return False

    @staticmethod
    def _find_mutations_in_ast(ast: DocumentNode, operation_name: Optional[str] = None) -> Set[str]:
        """Walk AST and collect all mutation field names, traversing fragments."""
        mutations = set()
        fragment_definitions = {}

        # First pass: collect all fragment definitions
        for definition in ast.definitions:
            if isinstance(definition, FragmentDefinitionNode):
                fragment_definitions[definition.name.value] = definition

        for definition in ast.definitions:
            if not isinstance(definition, OperationDefinitionNode):
                continue

            # If operation_name is specified, skip operations that don't match
            op_name = definition.name.value if definition.name else None
            if operation_name is not None and op_name != operation_name:
                continue

            # Anonymous operations: if operation_name is set and this operation
            # has no name, it can't be the targeted one — skip it.
            if operation_name is not None and op_name is None:
                continue

            if definition.operation.value != "mutation":
                continue

            # Extract top-level mutation fields (recursive through fragments)
            for selection in definition.selection_set.selections:
                GraphQLMutationAnalyzer._collect_field_names(
                    selection, mutations, fragment_definitions
                )

        return mutations

    @staticmethod
    def _collect_field_names(selection, mutations: Set[str], fragments: dict,
                              _visited_fragments: Optional[Set[str]] = None):
        """
        Recursively collect field names from selections, traversing fragments.

        Handles:
        - FieldNode: direct mutation field
        - FragmentSpreadNode: reference to a named fragment
        - InlineFragmentNode: inline fragment with nested selections

        Uses _visited_fragments to prevent infinite recursion from
        circular fragment spreads.
        """
        if _visited_fragments is None:
            _visited_fragments = set()

        if isinstance(selection, FieldNode):
            mutations.add(selection.name.value)

        elif isinstance(selection, FragmentSpreadNode):
            fragment = fragments.get(selection.name.value)
            if fragment and selection.name.value not in _visited_fragments:
                _visited_fragments.add(selection.name.value)
                for nested_selection in fragment.selection_set.selections:
                    GraphQLMutationAnalyzer._collect_field_names(
                        nested_selection, mutations, fragments, _visited_fragments
                    )

        elif isinstance(selection, InlineFragmentNode):
            if selection.selection_set:
                for nested_selection in selection.selection_set.selections:
                    GraphQLMutationAnalyzer._collect_field_names(
                        nested_selection, mutations, fragments, _visited_fragments
                    )

    @staticmethod
    def is_mutation(query: str) -> bool:
        """
        Check if query contains mutations.

        Returns False for unparseable or empty queries to prevent
        treating parser failures as mutations (security).
        """
        if not GraphQLMutationAnalyzer.is_parseable(query):
            return False
        return len(GraphQLMutationAnalyzer.extract_mutation_names(query)) > 0
