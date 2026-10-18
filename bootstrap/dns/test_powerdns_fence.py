"""Failure-boundary tests; real SQL permission behavior requires isolated rehearsal."""
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('fence', Path(__file__).with_name('powerdns-fence.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fixture_spec = importlib.util.spec_from_file_location('fixtures', Path(__file__).with_name('test_powerdns_snapshot.py'))
f = importlib.util.module_from_spec(fixture_spec); fixture_spec.loader.exec_module(f)
OP = '00000000-0000-4000-8000-000000000001'


def observation(fenced=True):
    return {'identity': f.SOURCE, 'writer_role': 'powerdns', 'schema_sha256': 'a' * 64,
        'role': {'name': 'powerdns', 'superuser': False, 'inherit': True, 'createrole': False,
                 'createdb': True, 'login': True, 'replication': False, 'bypassrls': False},
        'catalog_acl': {'database': [], 'schema': [], 'relations': []},
        'effective': {'connect': True,
            'tables': {t: {'SELECT': True, **dict.fromkeys(m.DML, not fenced)} for t in m.TABLES},
            'columns': {t: {'INSERT': not fenced, 'UPDATE': not fenced} for t in m.TABLES},
            'sequences': {s: {'SELECT': True, 'USAGE': not fenced, 'UPDATE': not fenced} for s in m.SEQUENCES}}}


class Database:
    def __init__(self, failure=None):
        self.events, self.phases, self.failure = [], [], failure
        self.fenced, self.saved = False, None
    def cursor(self): return Cursor(self)


class Cursor:
    def __init__(self, db): self.db=db
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def execute(self, sql, args=()):
        d=self.db;d.events.append(sql)
        if sql=='BEGIN': d.saved=d.fenced
        elif sql.startswith('LOCK TABLE') and d.failure=='blocked': raise TimeoutError('lock timeout')
        elif sql.startswith('REVOKE'):
            assert d.phases[-1]=='revoke-intent'
            d.fenced=True
            if d.failure=='revoke': raise ValueError('failed statement')
        elif sql=='COMMIT':
            assert d.phases[-1]=='commit-intent'
            d.saved=None
            if d.failure=='commit-reply-lost': raise OSError('uncertain commit')
        elif sql=='ROLLBACK' and d.saved is not None:
            d.fenced,d.saved=d.saved,None


class FenceTests(unittest.TestCase):
    def run_fence(self, database, preimage=None):
        plan={'identity':f.SOURCE,'writer_role':'powerdns','operation_id':OP,
              'before_sha256':m.digest(observation(False)) if preimage is None else preimage}
        def persist(phase, details): database.phases.append(phase)
        with patch.object(m,'acquire_lock'),patch.object(m,'release_lock'), \
             patch.object(m,'observe',side_effect=lambda *_:observation(database.fenced)):
            return m.fence_once(database,plan,persist)

    def test_success_keeps_select_and_never_changes_role_or_grants(self):
        d=Database();r=self.run_fence(d)
        self.assertEqual(d.phases,['revoke-intent','commit-intent','verified-fenced'])
        self.assertTrue(d.fenced);m.validate_receipt(r,f.SOURCE)
        self.assertEqual(sum(s.startswith('REVOKE') for s in d.events),13)
        self.assertFalse(any(s.startswith(('GRANT','ALTER','DROP')) for s in d.events))

    def test_lock_timeout_and_preimage_drift_cannot_revoke(self):
        for failure,preimage in [('blocked',None),(None,'b'*64)]:
            with self.subTest(failure=failure):
                d=Database(failure)
                with self.assertRaises((TimeoutError,m.snapshot.InvalidSnapshot)):
                    self.run_fence(d,preimage)
                self.assertFalse(d.fenced);self.assertFalse(d.phases)
                self.assertFalse(any(s.startswith('REVOKE') for s in d.events))

    def test_statement_failure_rolls_back_before_commit(self):
        d=Database('revoke')
        with self.assertRaises(ValueError):self.run_fence(d)
        self.assertFalse(d.fenced);self.assertEqual(d.phases,['revoke-intent'])
        self.assertNotIn('COMMIT',d.events)

    def test_unknown_commit_keeps_fence_and_never_claims_success(self):
        d=Database('commit-reply-lost')
        with self.assertRaises(OSError):self.run_fence(d)
        self.assertTrue(d.fenced)
        self.assertEqual(d.phases,['revoke-intent','commit-intent'])
        self.assertEqual(d.events.count('COMMIT'),1)
        self.assertFalse(any(s.startswith('GRANT') for s in d.events))

    def test_receipt_rejects_unsafe_role_even_with_recomputed_hash(self):
        receipt=m.make_receipt(OP,observation(False),observation())
        for field in ('superuser','createrole','replication','bypassrls'):
            changed=copy.deepcopy(receipt)
            for side in ('before','after'):
                changed[side]['role'][field]=True;changed[side+'_sha256']=m.digest(changed[side])
            with self.subTest(field=field),self.assertRaises(m.snapshot.InvalidSnapshot):
                m.validate_receipt(changed,f.SOURCE)

    def test_receipt_rejects_column_sequence_write_or_lost_read(self):
        for mode in ('column','sequence','select','connect'):
            changed=observation()
            if mode=='column':changed['effective']['columns']['records']['UPDATE']=True
            elif mode=='sequence':changed['effective']['sequences']['records_id_seq']['USAGE']=True
            elif mode=='select':changed['effective']['tables']['records']['SELECT']=False
            else:changed['effective']['connect']=False
            with self.subTest(mode=mode),self.assertRaises(m.snapshot.InvalidSnapshot):
                m.make_receipt(OP,observation(False),changed)

    def test_receipt_integrity_and_validity_are_bounded(self):
        r=m.make_receipt(OP,observation(False),observation())
        r['before']['role']['createdb']=False
        with self.assertRaises(m.snapshot.InvalidSnapshot):m.validate_receipt(r,f.SOURCE)
        r=m.make_receipt(OP,observation(False),observation());r['valid_until']=r['checked_at']
        with self.assertRaises(m.snapshot.InvalidSnapshot):m.validate_receipt(r,f.SOURCE)

    def test_final_snapshot_binds_exact_sql_fence(self):
        receipt=m.make_receipt(OP,observation(False),observation())
        tables,seq=f.fixture();at=m.snapshot.utc_now()
        result=m.snapshot.make_snapshot(f.SOURCE,tables,seq,seq,at,at,f.TX,final=True,fence=receipt)
        p=m.snapshot.validate_snapshot(result,f.SOURCE,require_final=True)
        self.assertEqual(p['capture']['fence'],receipt)
        self.assertEqual(p['capture']['fence_verification'],'sql-effective-privileges')
        with self.assertRaises(m.snapshot.InvalidSnapshot):
            m.snapshot.make_snapshot(f.SOURCE,tables,seq,seq,f.START,f.END,f.TX,final=True,fence=receipt)

    def test_live_capture_checks_fence_before_and_after_and_releases_lock(self):
        receipt=m.make_receipt(OP,observation(False),observation());conn=object()
        fake=SimpleNamespace(validate_receipt=lambda *_:None,acquire_lock=lambda *_:None,
            release_lock=lambda *_:None,assert_fenced=lambda *_:observation(),digest=m.digest)
        with patch.object(m.snapshot,'sql_fence_module',return_value=fake), \
             patch.object(m.snapshot,'_export_snapshot',return_value={'result':True}) as capture, \
             patch.object(fake,'release_lock') as unlock:
            self.assertEqual(m.snapshot.export_snapshot(conn,f.SOURCE,final=True,fence=receipt),{'result':True})
            capture.assert_called_once();unlock.assert_called_once()
        drift=observation();drift['catalog_acl']['schema']=['changed']
        with patch.object(m.snapshot,'sql_fence_module',return_value=fake), \
             patch.object(fake,'assert_fenced',side_effect=[observation(),drift]), \
             patch.object(m.snapshot,'_export_snapshot',return_value={}),patch.object(fake,'release_lock') as unlock:
            with self.assertRaises(m.snapshot.InvalidSnapshot):
                m.snapshot.export_snapshot(conn,f.SOURCE,final=True,fence=receipt)
            unlock.assert_called_once()
        with patch.object(m.snapshot,'sql_fence_module',return_value=fake), \
             patch.object(fake,'assert_fenced',return_value=drift), \
             patch.object(m.snapshot,'_export_snapshot') as capture,patch.object(fake,'release_lock') as unlock:
            with self.assertRaises(m.snapshot.InvalidSnapshot):
                m.snapshot.export_snapshot(conn,f.SOURCE,final=True,fence=receipt)
            capture.assert_not_called();unlock.assert_called_once()


if __name__=='__main__':unittest.main()
