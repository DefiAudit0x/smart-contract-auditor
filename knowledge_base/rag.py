"""
RAG Context Builder — injects relevant past vulnerabilities into AI prompts.
Supports Sentence-Transformers (semantic), TF-IDF (keyword), and keyword fallback.
"""
import logging
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from knowledge_base.db import KnowledgeBase

logger = logging.getLogger(__name__)

DEFAULT_MIN_CONFIDENCE = 0.25

CONTRACT_TYPE_KEYWORDS: Dict[str, List[str]] = {
    "ERC20": ["ERC20", "IERC20", "transfer", "transferFrom", "approve", "allowance", "totalSupply", "balanceOf"],
    "ERC721": ["ERC721", "IERC721", "safeTransferFrom", "mint", "tokenURI", "ownerOf"],
    "ERC1155": ["ERC1155", "IERC1155", "safeTransferFrom", "uri", "balanceOfBatch"],
    "Lending": ["lend", "borrow", "collateral", "liquidate", "interestRate", "loan"],
    "DEX/AMM": ["swap", "pool", "liquidity", "addLiquidity", "removeLiquidity", "reserve"],
    "Bridge": ["bridge", "relay", "crossChain", "message", "validator", "consensus"],
    "Staking": ["stake", "unstake", "reward", "withdrawStake", "delegate"],
    "Governance": ["propose", "vote", "quorum", "governor", "timelock"],
    "Vault": ["vault", "deposit", "withdraw", "share", "strategy", "harvest"],
    "Oracle": ["oracle", "priceFeed", "getPrice", "aggregator", "roundData"],
    "Multisig": ["multisig", "signature", "confirm", "execute", "threshold"],
    "Proxy": ["proxy", "delegatecall", "implementation", "upgradeTo", "UUPS"],
}


def detect_contract_type(code: str) -> str:
    code_lower = code.lower()
    scores = {}
    for ctype, keywords in CONTRACT_TYPE_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw.lower() in code_lower)
        if score > 0:
            scores[ctype] = score
    if not scores:
        return "General"
    return max(scores, key=scores.get)


def extract_key_functions(code: str) -> List[str]:
    funcs = re.findall(r"function\s+(\w+)\s*\(", code)
    return funcs[:15]


@dataclass
class _EmbCache:
    patterns: List[Dict]
    texts: List[str]
    model: object


class RAGContext:
    """Build relevant context from the Knowledge Base using confidence-aware retrieval."""

    def __init__(self, kb: KnowledgeBase, max_context_chars: int = 2000):
        self.kb = kb
        self.max_context_chars = max_context_chars
        self._cache: Optional[_EmbCache] = None
        self._pattern_count = 0

        try:
            self.min_confidence = float(
                os.environ.get("KB_RAG_MIN_CONFIDENCE", DEFAULT_MIN_CONFIDENCE)
            )
        except (TypeError, ValueError):
            self.min_confidence = DEFAULT_MIN_CONFIDENCE
        self.min_confidence = max(0.0, min(1.0, self.min_confidence))

        self._use_st = False
        self._use_tfidf = False
        _st_available = False
        try:
            import sentence_transformers
            _st_available = True
        except ImportError:
            pass

        if _st_available and os.environ.get("KB_USE_ST", "1") == "1":
            try:
                from sentence_transformers import SentenceTransformer
                self._st_model = SentenceTransformer("all-MiniLM-L6-v2")
                self._use_st = True
                logger.info("RAG: Sentence-Transformer model loaded (all-MiniLM-L6-v2)")
            except Exception as e:
                logger.warning(f"sentence-transformers load failed: {e}")

        if not self._use_st:
            try:
                from sklearn.feature_extraction.text import TfidfVectorizer
                self._TfidfVectorizer = TfidfVectorizer
                self._use_tfidf = True
                logger.info("RAG: using TF-IDF fallback")
            except ImportError:
                logger.info("scikit-learn not available, falling back to keyword search")

    def _eligible_patterns(self, patterns: List[Dict]) -> List[Dict]:
        """Keep only patterns whose stored confidence clears the RAG threshold."""
        eligible = []
        for pattern in patterns:
            confidence = pattern.get("confidence")
            if confidence is None:
                confidence = self.kb.get_pattern_confidence(pattern["id"]).get("confidence", 0.0)
            if confidence >= self.min_confidence:
                eligible.append(pattern)
        return eligible

    def _get_rag_patterns(self, contract_type: str = "", limit: int = 2000) -> List[Dict]:
        """Fetch confidence-filtered patterns without per-pattern DB queries."""
        if hasattr(self.kb, "get_patterns_for_rag"):
            return self.kb.get_patterns_for_rag(
                contract_type=contract_type,
                limit=limit,
                min_confidence=self.min_confidence,
            )
        # Legacy KB implementations without the explicit verification-aware
        # query are not safe RAG sources. Failing closed avoids re-introducing
        # candidate patterns when KB_RAG_MIN_CONFIDENCE is configured to 0.
        logger.warning("RAG disabled: KnowledgeBase lacks get_patterns_for_rag")
        return []

    def _encode_texts(self, texts: List[str]) -> object:
        if self._use_st:
            return self._st_model.encode(texts, convert_to_tensor=False, show_progress_bar=False)
        if self._use_tfidf:
            return self._vectorizer.fit_transform(texts)
        return None

    def _encode_query(self, text: str):
        if self._use_st:
            return self._st_model.encode([text], convert_to_tensor=False, show_progress_bar=False)[0]
        if self._use_tfidf:
            return self._vectorizer.transform([text])
        return None

    def _cosine_similarity(self, query_vec, matrix) -> List[float]:
        if self._use_st:
            import numpy as np
            query_norm = query_vec / (np.linalg.norm(query_vec) + 1e-10)
            matrix_norm = matrix / (np.linalg.norm(matrix, axis=1, keepdims=True) + 1e-10)
            return (matrix_norm @ query_norm).tolist()
        if self._use_tfidf:
            from sklearn.metrics.pairwise import cosine_similarity
            return cosine_similarity(query_vec, matrix).flatten().tolist()
        return []

    def update_embeddings(self):
        patterns = self._get_rag_patterns(limit=2000)
        if not patterns:
            self._cache = None
            self._pattern_count = 0
            return

        texts = []
        for pattern in patterns:
            texts.append(" ".join([
                pattern.get("name", ""),
                pattern.get("description", ""),
                str(pattern.get("code_snippet", "")),
                pattern.get("contract_type", ""),
            ]))

        if self._use_tfidf:
            self._vectorizer = self._TfidfVectorizer(max_features=1000, stop_words="english")

        encoded = self._encode_texts(texts)
        self._cache = _EmbCache(patterns=patterns, texts=texts, model=encoded)
        self._pattern_count = len(patterns)

    def _vector_retrieve(self, code: str, top_k: int) -> List[Dict]:
        eligible_count = len(self._get_rag_patterns(limit=2000))
        if self._cache is None or self._pattern_count != eligible_count:
            self.update_embeddings()
        if self._cache is None:
            return []

        query_vec = self._encode_query(code)
        if query_vec is None:
            return []

        scores = self._cosine_similarity(query_vec, self._cache.model)
        indexed = list(enumerate(scores))
        indexed.sort(key=lambda item: item[1], reverse=True)

        results = []
        for idx, score in indexed:
            if score > 0.05 and len(results) < top_k:
                results.append(self._cache.patterns[idx])
        return results

    def build_context(self, code: str, top_k: int = 3) -> str:
        contract_type = detect_contract_type(code)
        extract_key_functions(code)

        if self._use_st or self._use_tfidf:
            patterns = self._vector_retrieve(code, top_k)
        else:
            candidates = self.kb.find_similar_patterns(
                code[:200], contract_type, limit=max(top_k * 4, top_k)
            )
            patterns = self._eligible_patterns(candidates)[:top_k]

        if not patterns:
            return ""

        parts: List[str] = [f"## Similar Previous Vulnerability Patterns (Contract Type: {contract_type})", ""]
        for pattern in patterns:
            if len("\n".join(parts)) > self.max_context_chars:
                break

            line = (
                f"- **{pattern.get('name', '?')}** "
                f"[{pattern.get('severity', '?')}] — {pattern.get('description', '')[:200]}"
            )
            if pattern.get("fix_code"):
                line += f"\n  - Previous Fix: {pattern['fix_code'][:150]}"
            parts.append(line)

        parts.append("")
        return "\n".join(parts)
