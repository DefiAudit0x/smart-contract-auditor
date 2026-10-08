import os

from knowledge_base.rag import RAGContext


class FakeKB:
    def __init__(self):
        self.patterns = [
            {
                "id": 1,
                "name": "Unverified pattern",
                "severity": "High",
                "description": "Should not enter model context.",
                "fix_code": "",
                "contract_type": "General",
            },
            {
                "id": 2,
                "name": "Confirmed pattern",
                "severity": "High",
                "description": "Eligible for model context.",
                "fix_code": "use a guarded call",
                "contract_type": "General",
            },
        ]

    def get_pattern_confidence(self, pattern_id):
        confidence = {1: 0.1, 2: 0.9}[pattern_id]
        return {"confidence": confidence}

    def get_patterns_for_rag(self, contract_type="", limit=2000, min_confidence=0.0):
        return [
            pattern
            | {"confidence": self.get_pattern_confidence(pattern["id"])["confidence"]}
            for pattern in self.patterns[:limit]
            if self.get_pattern_confidence(pattern["id"])["confidence"] >= min_confidence
        ]


    def get_patterns_by_severity(self, severity="", limit=50):
        return self.patterns[:limit]

    def find_similar_patterns(self, code_snippet, contract_type="", limit=5):
        return self.patterns[:limit]


def test_rag_rejects_unconfirmed_patterns(monkeypatch):
    monkeypatch.setenv("KB_RAG_MIN_CONFIDENCE", "0.25")
    rag = RAGContext(FakeKB())
    rag._use_st = False
    rag._use_tfidf = False

    context = rag.build_context("contract Example {}")

    assert "Confirmed pattern" in context
    assert "Unverified pattern" not in context


def test_rag_threshold_is_configurable(monkeypatch):
    monkeypatch.setenv("KB_RAG_MIN_CONFIDENCE", "0.95")
    rag = RAGContext(FakeKB())

    assert rag.min_confidence == 0.95
    assert rag._eligible_patterns(FakeKB().patterns) == []


def test_invalid_rag_threshold_uses_safe_default(monkeypatch):
    monkeypatch.setenv("KB_RAG_MIN_CONFIDENCE", "not-a-number")
    rag = RAGContext(FakeKB())

    assert rag.min_confidence == 0.25


def test_rag_vector_cache_excludes_low_confidence_patterns(monkeypatch):
    monkeypatch.setenv("KB_RAG_MIN_CONFIDENCE", "0.25")
    rag = RAGContext(FakeKB())
    rag._use_st = False
    rag._use_tfidf = True

    rag.update_embeddings()

    assert rag._cache is not None
    assert [pattern["name"] for pattern in rag._cache.patterns] == ["Confirmed pattern"]
    assert rag._pattern_count == 1

def test_keyword_fallback_preserves_similarity_order(monkeypatch):
    monkeypatch.setenv("KB_RAG_MIN_CONFIDENCE", "0.25")
    rag = RAGContext(FakeKB())
    rag._use_st = False
    rag._use_tfidf = False

    relevant = {
        "id": 3,
        "name": "Relevant fallback pattern",
        "severity": "High",
        "description": "Returned first by the keyword similarity layer.",
        "fix_code": "",
        "contract_type": "General",
    }
    unrelated = {
        "id": 4,
        "name": "Lower relevance pattern",
        "severity": "Medium",
        "description": "Returned second by the keyword similarity layer.",
        "fix_code": "",
        "contract_type": "General",
    }

    rag.kb.find_similar_patterns = lambda code, contract_type="", limit=5: [relevant, unrelated]
    rag.kb.get_patterns_for_rag = lambda contract_type="", limit=2000, min_confidence=0.0: [
        relevant | {"confidence": 0.9},
        unrelated | {"confidence": 0.9},
    ]
    rag.kb.get_pattern_confidence = lambda pattern_id: {"confidence": 0.9}

    context = rag.build_context("contract Example {}")

    assert context.index("Relevant fallback pattern") < context.index("Lower relevance pattern")


def test_rag_fails_closed_without_verification_aware_kb(monkeypatch):
    monkeypatch.setenv("KB_RAG_MIN_CONFIDENCE", "0.0")

    class LegacyKB:
        def get_pattern_confidence(self, pattern_id):
            return {"confidence": 0.9}

        def get_patterns_by_severity(self, severity="", limit=50):
            return [{
                "id": 99,
                "name": "Legacy unverified pattern",
                "severity": "Critical",
                "description": "Must never enter RAG through a legacy fallback.",
                "fix_code": "",
                "contract_type": "General",
            }]

        def find_similar_patterns(self, code_snippet, contract_type="", limit=5):
            return [{
                "id": 99,
                "name": "Legacy unverified pattern",
                "severity": "Critical",
                "description": "Must never enter RAG through a legacy fallback.",
                "fix_code": "",
                "contract_type": "General",
            }]

    rag = RAGContext(LegacyKB())
    rag._use_st = False
    rag._use_tfidf = False

    assert rag.build_context("contract Example {}") == ""


def test_prune_sessions_deletes_feedback_before_expired_sessions(tmp_path):
    from knowledge_base.db import KnowledgeBase

    kb = KnowledgeBase(str(tmp_path / "kb.sqlite"))
    session_id = kb.start_session("old", "contract Old {}")
    assert session_id > 0
    kb.add_feedback(session_id, "Old finding", is_fp=True, comment="retention test")

    conn = kb._connect()
    conn.execute(
        "UPDATE audit_sessions SET created_at=? WHERE id=?",
        (0, session_id),
    )
    conn.commit()
    conn.close()

    assert kb.prune_sessions(keep_days=1) == 1

    conn = kb._connect()
    assert conn.execute(
        "SELECT COUNT(*) FROM audit_sessions WHERE id=?", (session_id,)
    ).fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM feedback WHERE session_id=?", (session_id,)
    ).fetchone()[0] == 0
    conn.close()


def test_prune_sessions_preserves_recent_feedback(tmp_path):
    from knowledge_base.db import KnowledgeBase

    kb = KnowledgeBase(str(tmp_path / "kb.sqlite"))
    session_id = kb.start_session("recent", "contract Recent {}")
    assert session_id > 0
    kb.add_feedback(session_id, "Recent finding", is_fp=False, comment="keep")

    assert kb.prune_sessions(keep_days=1) == 0

    conn = kb._connect()
    assert conn.execute(
        "SELECT COUNT(*) FROM feedback WHERE session_id=?", (session_id,)
    ).fetchone()[0] == 1
    conn.close()
