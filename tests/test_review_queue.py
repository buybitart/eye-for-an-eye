"""P9 review queue tests.

Most of these are safety tests rather than feature tests. The queue is the only
door a label can walk through, so the questions worth asking are: can a decision
become a label, can one source fill the queue, and can volume erase a person's
answer. The answer to all three must be no.
"""
from datetime import datetime, timedelta, timezone
import json
import unittest
import tempfile
from pathlib import Path

from eye_for_an_eye.decision.review_queue import (
    BENIGN_LIKE, IGNORE, LABEL_FOR_ANSWER, MALICIOUS_AUTOMATION_LIKE, QueueLimits, ReviewQueue,
    ReviewQueueError, STATES, SUMMARY_FEATURES, UNCERTAIN, UNREVIEWED, admission,
    behaviour_signature, source_key)

SECRET = b'x' * 32


def behaviour(**overrides):
    base = {name: 0.1 for name in SUMMARY_FEATURES}
    base.update(overrides)
    return base


class Clock:
    """A clock a test can move, so TTL is tested by passing time, not by sleeping."""

    def __init__(self, start=None):
        self.now = start or datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now = self.now + timedelta(**kwargs)


class QueueTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'review-queue.json'
        self.clock = Clock()

    def queue(self, **kwargs):
        limits = kwargs.pop('limits', None) or QueueLimits()
        return ReviewQueue(self.path, secret=SECRET, limits=limits, clock=self.clock, **kwargs)

    def offer(self, queue, source='10.0.0.1', *, priority=1.0, observations=20, **overrides):
        return queue.offer(source=source, behaviour=behaviour(**overrides),
                           evidence={'observations': observations, 'observation_seconds': 60.0},
                           priority=priority, reasons=('test',))


class TestAdmission(QueueTestCase):
    """What earns a place in the queue is uncertainty, never severity."""

    def test_a_blocked_decision_is_not_a_reason_to_review(self):
        priority, reasons = admission(fused_risk=0.95, acted=True, observations=50)
        self.assertEqual(priority, 0.0)
        self.assertEqual(reasons, ())

    def test_a_confident_benign_decision_is_not_a_reason_to_review(self):
        priority, _ = admission(math_score=0.02, model_score=0.03, fused_risk=0.02,
                                acted=False, observations=50)
        self.assertEqual(priority, 0.0)

    def test_disagreement_between_the_two_engines_earns_review(self):
        priority, reasons = admission(math_score=0.10, model_score=0.80, observations=50)
        self.assertGreater(priority, 0)
        self.assertTrue(any('disagree' in reason for reason in reasons))

    def test_a_middle_risk_earns_review(self):
        priority, reasons = admission(fused_risk=0.55, observations=50)
        self.assertGreater(priority, 0)
        self.assertTrue(any('middle' in reason for reason in reasons))

    def test_out_of_distribution_earns_review_without_calling_it_an_attack(self):
        _, reasons = admission(ood_score=0.7, ood_band='TAIL_BAND', observations=50)
        text = ' '.join(reasons)
        self.assertIn('outside the training distribution', text)
        self.assertNotIn('attack', text.lower())

    def test_an_anomaly_reason_says_unusual_is_not_bad(self):
        _, reasons = admission(anomaly_score=0.9, observations=50)
        self.assertTrue(any('not the same as bad' in reason for reason in reasons))

    def test_thin_evidence_lowers_priority(self):
        strong, _ = admission(fused_risk=0.55, observations=50)
        thin, _ = admission(fused_risk=0.55, observations=2)
        self.assertLess(thin, strong)


class TestAdmissionControl(QueueTestCase):
    """Every limit is a refusal."""

    def test_a_zero_priority_window_is_never_queued(self):
        queue = self.queue()
        result = self.offer(queue, priority=0.0)
        self.assertFalse(result['admitted'])
        self.assertEqual(queue.stats()['total'], 0)

    def test_too_little_evidence_is_refused(self):
        queue = self.queue(limits=QueueLimits(min_observations=5))
        result = self.offer(queue, observations=2)
        self.assertFalse(result['admitted'])
        self.assertIn('too little', result['reason'])

    def test_one_source_cannot_take_more_than_its_share(self):
        queue = self.queue(limits=QueueLimits(max_entries=100, per_source_entries=3))
        for index in range(10):
            self.offer(queue, source='10.0.0.9', ports_60s=index / 10)
        stats = queue.stats()
        self.assertEqual(stats['total'], 3)
        self.assertEqual(stats['largest_single_source'], 3)

    def test_a_flood_from_many_sources_still_stops_at_the_daily_limit(self):
        queue = self.queue(limits=QueueLimits(max_entries=500, per_source_entries=5,
                                              per_day_entries=7))
        for index in range(40):
            self.offer(queue, source=f'10.0.1.{index}', ports_60s=index / 100)
        self.assertEqual(queue.stats()['total'], 7)

    def test_the_daily_limit_resets_on_the_next_day(self):
        queue = self.queue(limits=QueueLimits(per_day_entries=2))
        for index in range(5):
            self.offer(queue, source=f'10.0.2.{index}', ports_60s=index / 100)
        self.assertEqual(queue.stats()['total'], 2)
        self.clock.advance(days=1)
        self.offer(queue, source='10.0.3.1', ports_60s=0.9)
        self.assertEqual(queue.stats()['total'], 3)

    def test_the_queue_never_grows_past_its_maximum(self):
        queue = self.queue(limits=QueueLimits(max_entries=5, per_source_entries=5,
                                              per_day_entries=500))
        for index in range(60):
            self.offer(queue, source=f'10.0.4.{index}', ports_60s=index / 100)
        self.assertLessEqual(queue.stats()['total'], 5)

    def test_the_same_behaviour_from_the_same_source_is_one_entry(self):
        queue = self.queue()
        first = self.offer(queue, source='10.0.5.1', ports_60s=0.4)
        second = self.offer(queue, source='10.0.5.1', ports_60s=0.4)
        self.assertTrue(first['admitted'])
        self.assertFalse(second['admitted'])
        self.assertEqual(second['reason'], 'already in the queue')
        self.assertEqual(second['occurrences'], 2)
        self.assertEqual(queue.stats()['total'], 1)

    def test_a_tiny_variation_does_not_buy_a_second_place(self):
        queue = self.queue()
        self.offer(queue, source='10.0.5.2', ports_60s=0.400)
        self.offer(queue, source='10.0.5.2', ports_60s=0.4001)
        self.assertEqual(queue.stats()['total'], 1)

    def test_a_real_difference_does_earn_a_second_place(self):
        queue = self.queue()
        self.offer(queue, source='10.0.5.3', ports_60s=0.10)
        self.offer(queue, source='10.0.5.3', ports_60s=0.90)
        self.assertEqual(queue.stats()['total'], 2)


class TestExpiry(QueueTestCase):
    def test_an_unreviewed_entry_expires(self):
        queue = self.queue(limits=QueueLimits(ttl_days=7))
        self.offer(queue, source='10.0.6.1')
        self.assertEqual(queue.stats()['total'], 1)
        self.clock.advance(days=8)
        self.offer(queue, source='10.0.6.2', ports_60s=0.8)
        remaining = [entry.source_key for entry in queue.entries()]
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0], source_key(SECRET, '10.0.6.2'))

    def test_a_reviewed_entry_does_not_expire(self):
        queue = self.queue(limits=QueueLimits(ttl_days=7))
        result = self.offer(queue, source='10.0.7.1')
        queue.record_review(result['entry_id'], BENIGN_LIKE, note='known backup job')
        self.clock.advance(days=400)
        queue.prune()
        self.assertEqual(len(queue.labelled()), 1)

    def test_volume_cannot_evict_a_persons_answer(self):
        queue = self.queue(limits=QueueLimits(max_entries=4, per_source_entries=4,
                                              per_day_entries=500))
        answered = self.offer(queue, source='10.0.8.1', ports_60s=0.11)
        queue.record_review(answered['entry_id'], MALICIOUS_AUTOMATION_LIKE)
        for index in range(50):
            self.offer(queue, source=f'10.0.9.{index}', ports_60s=index / 100)
        entries = queue.entries(limit=100)
        ids = [entry.entry_id for entry in entries]
        pending = [entry for entry in entries if entry.state == UNREVIEWED]
        self.assertIn(answered['entry_id'], ids)
        self.assertLessEqual(len(ids), 4)
        self.assertLessEqual(len(pending), 3)

    def test_a_queue_full_of_answers_stops_collecting_rather_than_dropping_them(self):
        queue = self.queue(limits=QueueLimits(max_entries=2, per_source_entries=2,
                                              per_day_entries=500))
        for index in range(2):
            result = self.offer(queue, source=f'10.0.10.{index}', ports_60s=index / 2)
            queue.record_review(result['entry_id'], BENIGN_LIKE)
        refused = self.offer(queue, source='10.0.11.1', ports_60s=0.95)
        self.assertFalse(refused['admitted'])
        self.assertIn('export them', refused['reason'])
        self.assertEqual(len(queue.labelled()), 2)


class TestLabelling(QueueTestCase):
    """A label exists only where a person answered."""

    def test_a_new_entry_starts_unreviewed(self):
        queue = self.queue()
        result = self.offer(queue, source='10.1.0.1')
        entry = queue.entries()[0]
        self.assertEqual(entry.state, UNREVIEWED)
        self.assertEqual(entry.reviewed_at, '')
        self.assertEqual(result['priority'], 1.0)

    def test_nothing_in_the_queue_is_labelled_until_a_person_answers(self):
        queue = self.queue()
        for index in range(5):
            self.offer(queue, source=f'10.1.1.{index}', ports_60s=index / 10)
        self.assertEqual(queue.labelled(), [])
        self.assertEqual(queue.stats()['labelled_by_a_person'], 0)

    def test_recording_an_answer_moves_the_state(self):
        queue = self.queue()
        result = self.offer(queue, source='10.1.2.1')
        entry = queue.record_review(result['entry_id'], MALICIOUS_AUTOMATION_LIKE,
                                    note='sequential port sweep')
        self.assertEqual(entry.state, MALICIOUS_AUTOMATION_LIKE)
        self.assertEqual(entry.reviewer_note, 'sequential port sweep')
        self.assertTrue(entry.reviewed_at)

    def test_uncertain_is_a_real_answer_and_is_always_low_confidence(self):
        queue = self.queue()
        result = self.offer(queue, source='10.1.3.1')
        entry = queue.record_review(result['entry_id'], UNCERTAIN, confidence='HIGH')
        self.assertEqual(entry.state, UNCERTAIN)
        self.assertEqual(entry.confidence, 'LOW')

    def test_a_reviewer_cannot_claim_deterministic_ground_truth(self):
        queue = self.queue()
        result = self.offer(queue, source='10.1.4.1')
        entry = queue.record_review(result['entry_id'], BENIGN_LIKE, confidence='HIGH')
        self.assertEqual(entry.confidence, 'MEDIUM')

    def test_ignore_produces_no_label_at_all(self):
        queue = self.queue()
        result = self.offer(queue, source='10.1.5.1')
        queue.record_review(result['entry_id'], IGNORE)
        self.assertEqual(queue.labelled(), [])
        self.assertNotIn(IGNORE, LABEL_FOR_ANSWER)

    def test_an_unknown_answer_is_refused(self):
        queue = self.queue()
        result = self.offer(queue, source='10.1.6.1')
        with self.assertRaises(ReviewQueueError):
            queue.record_review(result['entry_id'], 'MALICIOUS')
        with self.assertRaises(ReviewQueueError):
            queue.record_review(result['entry_id'], 'TEMP_BLOCK')

    def test_an_answer_can_be_taken_back(self):
        queue = self.queue()
        result = self.offer(queue, source='10.1.7.1')
        queue.record_review(result['entry_id'], BENIGN_LIKE)
        entry = queue.reset_review(result['entry_id'])
        self.assertEqual(entry.state, UNREVIEWED)
        self.assertEqual(queue.labelled(), [])

    def test_reviewing_an_unknown_entry_is_an_error(self):
        queue = self.queue()
        with self.assertRaises(ReviewQueueError):
            queue.record_review('does-not-exist', BENIGN_LIKE)


class TestExport(QueueTestCase):
    def test_the_export_carries_only_answered_rows(self):
        queue = self.queue()
        first = self.offer(queue, source='10.2.0.1', ports_60s=0.2)
        second = self.offer(queue, source='10.2.0.2', ports_60s=0.7)
        self.offer(queue, source='10.2.0.3', ports_60s=0.9)
        queue.record_review(first['entry_id'], BENIGN_LIKE)
        queue.record_review(second['entry_id'], MALICIOUS_AUTOMATION_LIKE)
        target = Path(self.directory.name) / 'labels.json'
        summary = queue.export_labels(target)
        document = json.loads(target.read_text(encoding='utf-8'))
        self.assertEqual(summary['rows'], 2)
        self.assertEqual({row['label'] for row in document['samples']},
                         {'benign_like', 'malicious_automation_like'})
        self.assertEqual({row['label_source'] for row in document['samples']}, {'manual_review'})

    def test_the_export_states_where_labels_came_from(self):
        queue = self.queue()
        target = Path(self.directory.name) / 'labels.json'
        queue.export_labels(target)
        document = json.loads(target.read_text(encoding='utf-8'))
        self.assertIn('human review only', document['label_origin'])


class TestPrivacy(QueueTestCase):
    def test_the_file_never_contains_the_address(self):
        queue = self.queue()
        self.offer(queue, source='198.51.100.77')
        text = self.path.read_text(encoding='utf-8')
        self.assertNotIn('198.51.100.77', text)

    def test_the_same_source_groups_to_the_same_key(self):
        self.assertEqual(source_key(SECRET, '203.0.113.5'), source_key(SECRET, '203.0.113.5'))
        self.assertNotEqual(source_key(SECRET, '203.0.113.5'), source_key(SECRET, '203.0.113.6'))

    def test_a_different_secret_gives_a_different_key(self):
        self.assertNotEqual(source_key(SECRET, '203.0.113.5'),
                            source_key(b'y' * 32, '203.0.113.5'))

    def test_a_queue_without_a_secret_refuses_to_group_sources(self):
        queue = ReviewQueue(self.path, secret=None, clock=self.clock)
        with self.assertRaises(ReviewQueueError):
            self.offer(queue)

    def test_only_behaviour_features_are_stored(self):
        queue = self.queue()
        queue.offer(source='10.3.0.1',
                    behaviour=dict(behaviour(), password='hunter2', user_agent='curl/8'),
                    evidence={'observations': 30}, priority=1.0)
        text = self.path.read_text(encoding='utf-8')
        self.assertNotIn('hunter2', text)
        self.assertNotIn('curl/8', text)

    def test_the_file_is_not_readable_by_other_users(self):
        queue = self.queue()
        self.offer(queue)
        self.assertEqual(self.path.stat().st_mode & 0o077, 0)


class TestFileHandling(QueueTestCase):
    def test_an_empty_path_reads_as_an_empty_queue(self):
        self.assertEqual(self.queue().entries(), [])
        self.assertEqual(self.queue().stats()['total'], 0)

    def test_a_corrupt_file_is_refused_rather_than_ignored(self):
        self.path.write_text('{not json', encoding='utf-8')
        with self.assertRaises(ReviewQueueError):
            self.queue().entries()

    def test_a_future_version_is_refused(self):
        self.path.write_text(json.dumps({'review_queue_version': 99, 'entries': []}),
                             encoding='utf-8')
        with self.assertRaises(ReviewQueueError):
            self.queue().entries()

    def test_an_unknown_state_is_refused(self):
        queue = self.queue()
        self.offer(queue)
        document = json.loads(self.path.read_text(encoding='utf-8'))
        document['entries'][0]['state'] = 'BLOCKED'
        self.path.write_text(json.dumps(document), encoding='utf-8')
        with self.assertRaises(ReviewQueueError):
            self.queue().entries()

    def test_the_file_records_what_it_may_and_may_not_do(self):
        queue = self.queue()
        self.offer(queue)
        document = json.loads(self.path.read_text(encoding='utf-8'))
        self.assertIn('cannot change a firewall', document['authority'])
        self.assertIn('cannot start training', document['authority'])


class TestLimitsValidation(unittest.TestCase):
    def test_impossible_limits_are_refused(self):
        for kwargs in ({'max_entries': 0}, {'max_entries': 10, 'per_source_entries': 11},
                       {'ttl_days': 0}, {'ttl_days': 400}, {'max_entries': 10, 'per_day_entries': 0}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ReviewQueueError):
                    QueueLimits(**kwargs)

    def test_the_states_are_exactly_the_documented_five(self):
        self.assertEqual(set(STATES), {UNREVIEWED, BENIGN_LIKE, MALICIOUS_AUTOMATION_LIKE,
                                       UNCERTAIN, IGNORE})


class TestSignature(unittest.TestCase):
    def test_a_missing_value_is_not_the_same_as_zero(self):
        self.assertNotEqual(behaviour_signature({'ports_60s': None}),
                            behaviour_signature({'ports_60s': 0.0}))

    def test_the_signature_is_stable(self):
        self.assertEqual(behaviour_signature(behaviour()), behaviour_signature(behaviour()))


class TestNoAutomaticLabelling(unittest.TestCase):
    """The prohibitions from the brief, asserted against the source itself."""

    def source(self):
        from eye_for_an_eye.decision import review_queue
        return Path(review_queue.__file__).read_text(encoding='utf-8')

    def test_no_code_path_turns_a_block_into_a_label(self):
        text = self.source()
        for forbidden in ('label = MALICIOUS', "label = 'malicious'", 'if blocked',
                          'would_block', 'auto_label'):
            self.assertNotIn(forbidden, text)

    def test_no_threshold_assigns_a_label(self):
        from eye_for_an_eye.decision.review_queue import ReviewQueue
        import inspect
        text = inspect.getsource(ReviewQueue.offer)
        self.assertNotIn('state=', text.replace('state=UNREVIEWED', ''))

    def test_offer_can_only_ever_create_an_unreviewed_entry(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        queue = ReviewQueue(Path(directory.name) / 'q.json', secret=SECRET)
        for score in (0.0, 0.5, 0.99, 1.0):
            queue.offer(source=f'10.4.0.{int(score * 100)}',
                        behaviour=behaviour(ports_60s=score),
                        evidence={'observations': 30}, priority=1.0,
                        analysis_only={'final_score': score, 'action': 'TEMP_BLOCK'})
        self.assertTrue(all(entry.state == UNREVIEWED for entry in queue.entries()))
        self.assertEqual(queue.labelled(), [])


if __name__ == '__main__':
    unittest.main()
