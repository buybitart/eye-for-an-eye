import concurrent.futures
import unittest

from eye_for_an_eye.enrichment.cache import TTLCache


class CacheTests(unittest.TestCase):
    def test_ttl_on_read_and_negative_value(self):
        now = [0.0]
        cache = TTLCache(2, 10, clock=lambda: now[0])
        self.assertTrue(cache.set("source", {"status": "not_found"}, ttl_seconds=2))
        self.assertEqual(cache.get("source")["status"], "not_found")
        now[0] = 2
        self.assertIsNone(cache.get("source"))
        self.assertEqual(cache.metrics["expired"], 1)

    def test_lru_and_entry_bound(self):
        cache = TTLCache(2, 10)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.get("a")
        cache.set("c", 3)
        self.assertIsNone(cache.get("b"))
        for i in range(1000):
            cache.set(str(i), i)
        self.assertLessEqual(len(cache), 2)
        self.assertGreater(cache.metrics["eviction"], 0)

    def test_expired_length_and_replacement(self):
        now = [0.0]
        cache = TTLCache(2, 1, clock=lambda: now[0])
        cache.set("a", 1)
        cache.set("a", 2)
        self.assertEqual(len(cache), 1)
        now[0] = 2
        self.assertEqual(len(cache), 0)

    def test_byte_budget_rejects_oversized(self):
        cache = TTLCache(5, 10, max_bytes=512)
        self.assertFalse(cache.set("large", b"x" * 2048))
        self.assertEqual(len(cache), 0)
        self.assertEqual(cache.metrics["rejected"], 1)

    def test_byte_budget_isolated_from_mutation(self):
        cache = TTLCache(5, 10, max_bytes=1024)
        value = {"text": "small"}
        self.assertTrue(cache.set("a", value))
        value["text"] = "x" * 10000
        returned = cache.get("a")
        returned["text"] = "y" * 10000
        self.assertEqual(cache.get("a"), {"text": "small"})
        self.assertLessEqual(cache.current_bytes, 1024)

    def test_thread_safety(self):
        cache = TTLCache(16, 10)
        def update(offset):
            for i in range(500):
                cache.set((offset, i), i)
                cache.get((offset, i))
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(update, range(4)))
        self.assertLessEqual(len(cache), 16)

    def test_invalid_limits(self):
        for kwargs in ({"max_entries": 0}, {"ttl_seconds": 0}, {"ttl_seconds": float("nan")}, {"max_bytes": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                TTLCache(**kwargs)

    def test_metrics_snapshot(self):
        cache = TTLCache()
        self.assertIsNone(cache.get("absent"))
        metrics = cache.metrics
        metrics["miss"] = 999
        self.assertEqual(cache.metrics["miss"], 1)


if __name__ == "__main__":
    unittest.main()
