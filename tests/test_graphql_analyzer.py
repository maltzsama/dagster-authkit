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

    def test_operation_name_filters_query(self):
        """When operationName targets a query, mutations from other ops are ignored."""
        query = """
        query GetRuns { runs { runId } }
        mutation DeleteAll { deleteRun(runId: "x") }
        """
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(query, operation_name="GetRuns")
        assert mutations == set()

    def test_operation_name_filters_mutation(self):
        """When operationName targets a mutation, only that mutation's fields are checked."""
        query = """
        query GetRuns { runs { runId } }
        mutation DeleteAll { deleteRun(runId: "x") }
        """
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(
            query, operation_name="DeleteAll"
        )
        assert mutations == {"deleteRun"}

    def test_named_mutation(self):
        """Named (aliased) mutations should still have their fields extracted."""
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(
            "mutation MyMutation { launchRun { runId } }"
        )
        assert mutations == {"launchRun"}

    def test_query_not_mutation(self):
        """A 'query' operation should not produce mutation names."""
        mutations = GraphQLMutationAnalyzer.extract_mutation_names("query { runs { runId } }")
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
        """An unparseable query should return the sentinel set."""
        mutations = GraphQLMutationAnalyzer.extract_mutation_names("not valid graphql {{{")
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
        """Empty/unparseable queries are not mutations (security fix)."""
        assert GraphQLMutationAnalyzer.is_mutation("") is False


class TestIsParseable:
    """Verifies the is_parseable validation method."""

    def test_valid_query_is_parseable(self):
        """A valid GraphQL query should be parseable."""
        assert GraphQLMutationAnalyzer.is_parseable("query { runs { runId } }") is True

    def test_empty_string_is_not_parseable(self):
        """An empty string is not parseable."""
        assert GraphQLMutationAnalyzer.is_parseable("") is False

    def test_whitespace_is_not_parseable(self):
        """Whitespace-only input is not parseable."""
        assert GraphQLMutationAnalyzer.is_parseable("   \n\t  ") is False

    def test_malformed_query_is_not_parseable(self):
        """A malformed query is not parseable."""
        assert GraphQLMutationAnalyzer.is_parseable("not valid {{{") is False

    def test_none_is_not_parseable(self):
        """None is not parseable."""
        assert GraphQLMutationAnalyzer.is_parseable(None) is False


class TestFragmentTraversal:
    """Verifies that fragment references and inline fragments are traversed."""

    def test_named_fragment_spread(self):
        """Mutations inside named fragments should be detected."""
        query = """
        mutation {
            ...LaunchOps
        }
        fragment LaunchOps on Mutation {
            launchRun(input: {})
        }
        """
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(query)
        assert "launchRun" in mutations

    def test_inline_fragment(self):
        """Mutations inside inline fragments should be detected."""
        query = """
        mutation {
            ... on Mutation {
                terminateRun(runId: "123")
            }
        }
        """
        mutations = GraphQLMutationAnalyzer.extract_mutation_names(query)
        assert "terminateRun" in mutations
