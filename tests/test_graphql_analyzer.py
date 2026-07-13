"""
Unit tests for core/graphql_analyzer.py

Covers:
- extract_mutation_names for single and multiple mutations
- Empty queries, queries without mutations
- is_mutation convenience method
- Invalid/unparseable query handling
"""

import pytest

from dagster_authkit.core.graphql_analyzer import GraphQLMutationAnalyzer


class TestExtractMutationNames:
    """Verifies mutation name extraction from GraphQL queries."""

    def test_single_mutation(self):
        """A single mutation should be extracted by name."""
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(
            "mutation { launchRun(input: {}) }"
        )
        assert mutations == {"launchRun"}

    def test_multiple_mutations(self):
        """Multiple mutations in one query should all be extracted."""
        query = """
        mutation {
            launchRun(input: {})
            deleteRun(runId: "123")
        }
        """
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(query)
        assert mutations == {"launchRun", "deleteRun"}

    def test_nested_mutations_only_top_level(self):
        """Only top-level mutation names should be extracted, not nested fields."""
        query = """
        mutation {
            launchRun(input: {
                someNestedField: "value"
            })
        }
        """
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(query)
        assert mutations == {"launchRun"}
        assert "someNestedField" not in mutations

    def test_named_mutation(self):
        """Named (aliased) mutations should still have their fields extracted."""
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(
            "mutation MyMutation { launchRun { runId } }"
        )
        assert mutations == {"launchRun"}

    def test_query_not_mutation(self):
        """A 'query' operation should not produce mutation names."""
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(
            "query { runs { runId } }"
        )
        assert mutations == set()

    def test_empty_query(self):
        """An empty string is unparseable, returns sentinel set."""
        mutations = GraphQLMutationAnalyzer.extract_mutation_names("")
        assert "__UNPARSEABLE_QUERY__" in mutations

    def test_only_whitespace(self):
        """Whitespace-only input is unparseable, returns sentinel set."""
        mutations = GraphQLMutationAnalyzer.extract_mutation_names("   \n\t  ")
        assert "__UNPARSEABLE_QUERY__" in mutations

    def test_unparseable_query(self):
        """An unparseable query should return a sentinel set."""
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(
            "not valid graphql {{{"
        )
        assert "__UNPARSEABLE_QUERY__" in mutations

    def test_multiple_mutation_operations(self):
        """Query with multiple mutation definitions should extract all."""
        query = """
        mutation {
            launchRun(input: {})
            terminateRun(runId: "456")
            startSchedule(scheduleId: "789")
        }
        """
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(query)
        assert mutations == {"launchRun", "terminateRun", "startSchedule"}

    def test_returns_set_type(self):
        """The return type should always be a set."""
        result = GraphQLMutationAnalyzer.extract_mutation_names("mutation { launchRun }")
        assert isinstance(result, set)


class TestIsMutation:
    """Verifies the is_mutation convenience method."""

    def test_is_mutation_true(self):
        """A mutation query should return True."""
        assert GraphQLMutationAnalyzer.is_mutation("mutation { launchRun }") is True

    def test_is_mutation_false(self):
        """A non-mutation query should return False."""
        assert GraphQLMutationAnalyzer.is_mutation("query { runs { runId } }") is False

    def test_is_mutation_empty(self):
        """An empty query triggers unparseable sentinel, which contains 1 element -> True."""
        assert GraphQLMutationAnalyzer.is_mutation("") is True
