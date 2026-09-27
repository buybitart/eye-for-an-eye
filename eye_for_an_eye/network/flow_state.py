"""Bounded SYN/SYN-ACK/ACK evidence, no handshake assumption from a lone ACK.

P15.4 gives this object one more job: pairing an authentication attempt with the
answer it received. That pairing belongs here because this is the only place
that knows both the direction of a packet and which conversation it belongs to.
A request says "someone tried to authenticate"; only the reply on the same flow
says whether it worked, and only this object can tell that reply from an
unrelated one.

The pairing is deliberately narrow. One pending attempt per flow, cleared the
moment it is answered, never carried across connections. A reply this sensor
cannot read — anything inside TLS — resolves to nothing rather than to a
failure, which is the distinction `decision/auth.py` exists to protect.
"""
from ..enrichment.cache import TTLCache


class FlowEvidence:
    def __init__(self, entries=10000, ttl=900, *, clock=None):
        options = {'clock': clock} if clock else {}
        self.cache = TTLCache(entries, ttl, max_bytes=4_194_304, **options)

    def observe(self, flow, flags, seq, ack, size, *, auth=None):
        """Flow evidence, plus an authentication outcome when one is resolvable.

        `auth` is what the payload parser saw in this packet: whether it was an
        authentication attempt, its mechanism and pseudonymous principal, and
        whether it reads as a server's verdict. Which half applies depends on the
        direction, which only this method knows.
        """
        result = {'completed_handshake': False, 'response_continuation': False, 'retry_observed': False}
        auth = auth or {}
        key = flow.tuple()
        reverse = (flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, flow.transport)
        if flags & 2 and not flags & 16:
            previous = self.cache.get(key)
            result['retry_observed'] = bool(previous and previous['syn_seq'] == seq)
            state = previous if result['retry_observed'] else {'syn_seq': seq, 'server_seq': None, 'complete': False,
                'response_seen': False, 'last_client_seq': None, 'auth_pending': None}
            self.cache.set(key, state)
            return result
        state = self.cache.get(key)
        inbound = state is not None
        if state is None:
            state = self.cache.get(reverse)
            key = reverse
        if state is None:
            return result
        state.setdefault('auth_pending', None)
        if not inbound:
            result['direction'] = 'response'
            if flags & 18 == 18 and ack == (state['syn_seq'] + 1) & 0xffffffff:
                state['server_seq'] = seq
            if size:
                state['response_seen'] = True
                # The server has answered. If an attempt is waiting on this flow
                # and the answer is one this sensor can read, the pair resolves
                # here and the attempt is cleared. An unreadable answer leaves it
                # pending: the attempt happened, the outcome is simply unknown.
                outcome = auth.get('auth_response_result')
                pending = state['auth_pending']
                if pending and outcome:
                    result['auth_result'] = outcome
                    result['auth_mechanism'] = pending.get('mechanism', '')
                    if pending.get('principal'):
                        result['auth_principal'] = pending['principal']
                    state['auth_pending'] = None
        else:
            if (flags & 16 and not flags & 2 and state['server_seq'] is not None and not state['complete']
                    and ack == (state['server_seq'] + 1) & 0xffffffff and seq == (state['syn_seq'] + 1) & 0xffffffff):
                state['complete'] = True
                result['completed_handshake'] = True
            if size:
                result['response_continuation'] = state['response_seen']
                result['retry_observed'] = state['last_client_seq'] == seq
                state['last_client_seq'] = seq
                if auth.get('auth_attempted'):
                    # One pending attempt per flow. A client that sends a second
                    # attempt before the first is answered replaces it rather
                    # than queueing: an unbounded queue here would be a bound
                    # the attacker chooses.
                    state['auth_pending'] = {'mechanism': auth.get('auth_mechanism', ''),
                                             'principal': auth.get('auth_principal', '')}
        self.cache.set(key, state)
        return result
