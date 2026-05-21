"""Tests for keyword validation and filtering."""

import pytest
from wevibe_sdk.keyword_filter import (
    is_structurally_valid,
    is_semantically_valid,
    is_valid_keyword,
    filter_keywords,
    normalize_filtered,
    scrub_keywords,
    validate_keyword_kinds,
    KNOWN_STACK_TERMS,
    KNOWN_PATTERN_TERMS,
)


class TestStructuralValidation:
    def test_valid_technology_name(self):
        assert is_structurally_valid("fastapi") is True

    def test_valid_compound_term(self):
        assert is_structurally_valid("exponential_backoff") is True

    def test_valid_two_segment(self):
        assert is_structurally_valid("redis_caching") is True

    def test_valid_three_segment(self):
        assert is_structurally_valid("circuit_breaker_pattern") is True

    def test_rejects_empty(self):
        assert is_structurally_valid("") is False

    def test_rejects_none(self):
        assert is_structurally_valid(None) is False

    def test_rejects_too_long(self):
        assert is_structurally_valid("a" * 50) is False

    def test_rejects_single_char(self):
        assert is_structurally_valid("a") is False

    def test_rejects_spaces(self):
        assert is_structurally_valid("exponential backoff") is False

    def test_rejects_leading_underscore(self):
        assert is_structurally_valid("_activatetab") is False

    def test_rejects_trailing_underscore(self):
        assert is_structurally_valid("test_") is False

    def test_rejects_special_chars(self):
        assert is_structurally_valid("socket.io") is False

    def test_rejects_dashes(self):
        assert is_structurally_valid("socket-io") is False

    def test_rejects_pure_number(self):
        assert is_structurally_valid("80") is False

    def test_rejects_number_suffix(self):
        assert is_structurally_valid("30s") is False

    def test_rejects_uppercase(self):
        assert is_structurally_valid("FastAPI") is False

    def test_rejects_mixed_case(self):
        assert is_structurally_valid("RedisCache") is False

    def test_rejects_leading_digit(self):
        assert is_structurally_valid("2fa") is False

    def test_rejects_version_string(self):
        assert is_structurally_valid("v2") is False


class TestSemanticValidation:
    def test_accepts_specific_tech(self):
        assert is_semantically_valid("redis") is True

    def test_accepts_specific_pattern(self):
        assert is_semantically_valid("circuit_breaker") is True

    def test_accepts_compound_with_specific_term(self):
        assert is_semantically_valid("redis_caching") is True

    def test_rejects_generic_single_server(self):
        assert is_semantically_valid("server") is False

    def test_rejects_generic_single_error(self):
        assert is_semantically_valid("error") is False

    def test_rejects_generic_single_data(self):
        assert is_semantically_valid("data") is False

    def test_rejects_generic_single_config(self):
        assert is_semantically_valid("config") is False

    def test_rejects_generic_single_test(self):
        assert is_semantically_valid("test") is False

    def test_rejects_generic_single_code(self):
        assert is_semantically_valid("code") is False

    def test_rejects_subjective_prefix_aggressive(self):
        assert is_semantically_valid("aggressive_timeouts") is False

    def test_rejects_subjective_prefix_proper(self):
        assert is_semantically_valid("proper_error_handling") is False

    def test_rejects_subjective_prefix_simple(self):
        assert is_semantically_valid("simple_auth") is False

    def test_rejects_project_identifier_leading_underscore(self):
        assert is_semantically_valid("_activatetab") is False

    def test_rejects_file_extension_ts(self):
        assert is_semantically_valid("position_manager_ts") is False

    def test_rejects_file_extension_js(self):
        assert is_semantically_valid("utils_js") is False

    def test_rejects_sentence_fragment_too_many_segments(self):
        assert is_semantically_valid("all_error_handling_should_send_messages_back") is False

    def test_rejects_all_generic_compound(self):
        assert is_semantically_valid("error_handling") is False

    def test_accepts_mixed_compound_with_specific_term(self):
        assert is_semantically_valid("jwt_authentication") is True

    def test_rejects_generic_verbs(self):
        assert is_semantically_valid("create") is False

    def test_rejects_generic_verbs_compound(self):
        assert is_semantically_valid("create_data") is False


class TestCombinedValidation:
    def test_is_valid_keyword_full_check(self):
        assert is_valid_keyword("fastapi") is True
        assert is_valid_keyword("redis") is True
        assert is_valid_keyword("exponential_backoff") is True
        assert is_valid_keyword("aggressive_timeouts") is False
        assert is_valid_keyword("_activatetab") is False
        assert is_valid_keyword("80_percent_threshold") is False
        assert is_valid_keyword("server") is False
        assert is_valid_keyword("redis_server") is True
        assert is_valid_keyword("websocket") is True
        assert is_valid_keyword("docker") is True
        assert is_valid_keyword("kubernetes") is True


class TestFilteringAndNormalization:
    def test_scrub_removes_junk(self):
        input_kw = [
            {"term": "fastapi", "weight": 0.3, "role": "chosen"},
            {"term": "redis", "weight": 0.2, "role": "chosen"},
            {"term": "aggressive_timeouts", "weight": 0.15, "role": "context"},
            {"term": "_activatetab", "weight": 0.1, "role": "context"},
            {"term": "server", "weight": 0.1, "role": "context"},
            {"term": "circuit_breaker", "weight": 0.05, "role": "chosen"},
            {"term": "error", "weight": 0.04, "role": "context"},
            {"term": "80", "weight": 0.03, "role": "context"},
            {"term": "exponential_backoff", "weight": 0.02, "role": "chosen"},
            {"term": "socket.io", "weight": 0.01, "role": "context"},
        ]
        result = scrub_keywords(input_kw)
        result_terms = {kw["term"] for kw in result}
        assert "fastapi" in result_terms
        assert "redis" in result_terms
        assert "circuit_breaker" in result_terms
        assert "exponential_backoff" in result_terms
        assert "aggressive_timeouts" not in result_terms
        assert "_activatetab" not in result_terms
        assert "server" not in result_terms
        assert "error" not in result_terms
        assert "80" not in result_terms
        assert "socket.io" not in result_terms
        total_weight = sum(kw["weight"] for kw in result)
        assert abs(total_weight - 1.0) < 0.0001

    def test_scrub_preserves_roles(self):
        input_kw = [
            {"term": "fastapi", "weight": 0.6, "role": "chosen"},
            {"term": "redis", "weight": 0.3, "role": "rejected"},
            {"term": "ws", "weight": 0.1, "role": "context"},
        ]
        result = scrub_keywords(input_kw)
        role_map = {kw["term"]: kw["role"] for kw in result}
        assert role_map["fastapi"] == "chosen"
        assert role_map["redis"] == "rejected"
        assert role_map["ws"] == "context"

    def test_scrub_empty_after_filter(self):
        input_kw = [
            {"term": "server", "weight": 0.5, "role": "context"},
            {"term": "error", "weight": 0.3, "role": "context"},
            {"term": "data", "weight": 0.2, "role": "context"},
        ]
        result = scrub_keywords(input_kw)
        assert result == []

    def test_scrub_renormalizes(self):
        input_kw = [
            {"term": "fastapi", "weight": 0.36, "role": "chosen"},
            {"term": "redis", "weight": 0.24, "role": "chosen"},
            {"term": "aggressive_timeouts", "weight": 0.20, "role": "context"},
            {"term": "_activatetab", "weight": 0.20, "role": "context"},
        ]
        result = scrub_keywords(input_kw)
        valid_terms = {kw["term"] for kw in result}
        assert valid_terms == {"fastapi", "redis"}
        total_weight = sum(kw["weight"] for kw in result)
        assert abs(total_weight - 1.0) < 0.0001
        fastapi_weight = next(kw["weight"] for kw in result if kw["term"] == "fastapi")
        redis_weight = next(kw["weight"] for kw in result if kw["term"] == "redis")
        assert fastapi_weight == pytest.approx(0.6)
        assert redis_weight == pytest.approx(0.4)

    def test_filter_keywords_simple(self):
        input_kw = [
            {"term": "fastapi", "weight": 0.5, "role": "chosen"},
            {"term": "server", "weight": 0.3, "role": "context"},
            {"term": "redis", "weight": 0.2, "role": "chosen"},
        ]
        result = filter_keywords(input_kw)
        assert len(result) == 2
        result_terms = {kw["term"] for kw in result}
        assert "fastapi" in result_terms
        assert "redis" in result_terms
        assert "server" not in result_terms

    def test_normalize_filtered_empty(self):
        assert normalize_filtered([]) == []

    def test_normalize_filtered_preserves_order(self):
        input_kw = [
            {"term": "fastapi", "weight": 0.6, "role": "chosen"},
            {"term": "redis", "weight": 0.3, "role": "chosen"},
            {"term": "ws", "weight": 0.1, "role": "context"},
        ]
        result = normalize_filtered(input_kw)
        assert result[0]["term"] == "fastapi"
        assert result[1]["term"] == "redis"
        assert result[2]["term"] == "ws"

    def test_scrub_sorts_by_weight_descending(self):
        input_kw = [
            {"term": "redis", "weight": 0.1, "role": "chosen"},
            {"term": "fastapi", "weight": 0.5, "role": "chosen"},
            {"term": "ws", "weight": 0.4, "role": "chosen"},
        ]
        result = scrub_keywords(input_kw)
        weights = [kw["weight"] for kw in result]
        assert weights == sorted(weights, reverse=True)


class TestValidateKeywordKinds:
    """Tests for the kind reference list guardrail."""

    def test_known_stack_term_overridden(self):
        """LLM says 'redis' is pattern → corrected to stack."""
        keywords = [{"term": "redis", "weight": 0.5, "role": "chosen", "kind": "pattern"}]
        result = validate_keyword_kinds(keywords)
        assert result[0]["kind"] == "stack"

    def test_known_pattern_term_overridden(self):
        """LLM says 'exponential_backoff' is stack → corrected to pattern."""
        keywords = [
            {"term": "exponential_backoff", "weight": 0.5, "role": "chosen", "kind": "stack"}
        ]
        result = validate_keyword_kinds(keywords)
        assert result[0]["kind"] == "pattern"

    def test_novel_term_keeps_llm_kind(self):
        """Unknown term keeps whatever the LLM assigned."""
        keywords = [{"term": "zorblax_cache", "weight": 0.5, "role": "chosen", "kind": "stack"}]
        result = validate_keyword_kinds(keywords)
        assert result[0]["kind"] == "stack"

    def test_missing_kind_defaults_to_pattern(self):
        """Keyword with no kind field gets 'pattern'."""
        keywords = [{"term": "something", "weight": 0.5, "role": "chosen"}]
        result = validate_keyword_kinds(keywords)
        assert result[0]["kind"] == "pattern"

    def test_preserves_other_fields(self):
        """term, weight, role are not modified."""
        keywords = [{"term": "redis", "weight": 0.5, "role": "chosen", "kind": "pattern"}]
        result = validate_keyword_kinds(keywords)
        assert result[0]["term"] == "redis"
        assert result[0]["weight"] == 0.5
        assert result[0]["role"] == "chosen"

    def test_known_stack_terms_list_not_empty(self):
        """KNOWN_STACK_TERMS contains substantial entries."""
        assert len(KNOWN_STACK_TERMS) >= 100

    def test_known_pattern_terms_list_not_empty(self):
        """KNOWN_PATTERN_TERMS contains substantial entries."""
        assert len(KNOWN_PATTERN_TERMS) >= 50

    def test_no_overlap_between_lists(self):
        """Stack and pattern lists don't share terms."""
        overlap = KNOWN_STACK_TERMS & KNOWN_PATTERN_TERMS
        assert len(overlap) == 0, f"Terms in both lists: {overlap}"
