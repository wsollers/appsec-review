from __future__ import annotations
from pathlib import Path
import sys, unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import pool_launcher

class PoolLauncherTests(unittest.TestCase):
    def test_expands_launches_waits_and_reverifies_in_order(self):
        calls=[]
        plan=mock.Mock(); plan.pool_directory="pool-a"; plan.manifest={"expansion_sha256":"sha256:"+"a"*64}; plan.instances=(1,2); plan.pool_root.return_value=Path("/run/pool-a")
        verified=mock.Mock(); verified.instances=(1,2); verified.manifest={"manifest_sha256":"sha256:"+"b"*64,"outcome":"COMPLETE"}
        context=mock.Mock(); runtime=mock.Mock(); runtime.rendezvous_parent=Path("/run/rendezvous")
        with mock.patch.object(pool_launcher.specification,"expand_pool",side_effect=lambda *a,**k:(calls.append("expand"),plan)[1]), mock.patch.object(pool_launcher.rendezvous,"run_rendezvous",side_effect=lambda *a,**k:calls.append("launch")), mock.patch.object(pool_launcher.rendezvous,"load_verified_manifest",side_effect=lambda *a,**k:(calls.append("verify"),verified)[1]):
            result=pool_launcher.launch({"schema":"fixture"},context=context,runtime=runtime)
        self.assertEqual(calls,["expand","launch","verify"]); self.assertEqual(result.outcome,"COMPLETE"); self.assertEqual(result.instance_count,2)
        plan.pool_root.assert_called_once_with(context)
    def test_population_mismatch_fails_closed(self):
        plan=mock.Mock(); plan.pool_directory="pool-a"; plan.manifest={"expansion_sha256":"sha256:"+"a"*64}; plan.instances=(1,2); plan.pool_root.return_value=Path("/run/pool-a")
        verified=mock.Mock(); verified.instances=(1,); verified.manifest={"manifest_sha256":"sha256:"+"b"*64,"outcome":"DEGRADED"}
        runtime=mock.Mock(); runtime.rendezvous_parent=Path("/run/rendezvous")
        with mock.patch.object(pool_launcher.specification,"expand_pool",return_value=plan), mock.patch.object(pool_launcher.rendezvous,"run_rendezvous"), mock.patch.object(pool_launcher.rendezvous,"load_verified_manifest",return_value=verified):
            with self.assertRaisesRegex(Exception,"population"): pool_launcher.launch({},context=mock.Mock(),runtime=runtime)

if __name__=="__main__": unittest.main()
