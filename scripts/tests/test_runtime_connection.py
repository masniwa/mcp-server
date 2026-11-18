"""Offline CLI tests. All paths/data are disposable; live Burp is never touched.

Configure tests mock only OS liveness queries inside their own PowerShell process.
The production script has no test/bypass flag. Separate cases exercise real refusal
branches with simulated running/unknown processes. No listener or server is started.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

PROJECT=Path(__file__).resolve().parents[2]
TEMP=PROJECT.parent/'temp'
PWSH=shutil.which('pwsh.exe') or shutil.which('pwsh')

def quote(value):
    return "'"+str(value).replace("'","''")+"'"

class RuntimeConnectionTest(unittest.TestCase):
    def setUp(self):
        TEMP.mkdir(exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(dir=TEMP)
        self.base=Path(self.tmp.name)/'clone 日本語 space'
        self.mcp=self.base/'mcp-server-latest'
        self.cph=self.base/'different CPH'
        (self.mcp/'build/libs').mkdir(parents=True)
        (self.mcp/'scripts').mkdir()
        shutil.copy2(PROJECT/'configure-runtime.ps1',self.mcp)
        shutil.copy2(PROJECT/'check-install.ps1',self.mcp)
        shutil.copy2(PROJECT/'scripts/RuntimeConnection.ps1',self.mcp/'scripts')
        self.jar=self.mcp/'build/libs/burp-mcp-all.jar'
        with zipfile.ZipFile(self.jar,'w') as archive:
            archive.writestr('diagnostic-profile.properties','authorizationMode=REVIEW\n')
        self.cph.mkdir()
        for name in ['CPH_Managed.py','CPH_API_v0_2.py','CustomParamHandler_marged_api_v0.2.py']:
            (self.cph/name).write_text('# test fixture\n',encoding='utf-8')
        self.pointer=self.cph/'runtime/cph-connection.json'
        self.secrets={'worker':'w'*48,'cph':'c'*48}
        self.env={k:v for k,v in os.environ.items() if not k.startswith('BURP_DIAG_')}

    def tearDown(self):
        self.tmp.cleanup()

    def initialize(self):
        runtime=self.mcp/'runtime'; runtime.mkdir(exist_ok=True)
        (runtime/'settings.json').write_text('{"schemaVersion":1,"authorizationMode":"REVIEW","verifiedCapabilities":[]}',encoding='utf-8')
        (runtime/'operator-secrets.json').write_text(json.dumps(self.secrets),encoding='utf-8')

    def stale(self):
        self.pointer.parent.mkdir(exist_ok=True)
        self.pointer.write_text('{"runtimeDirectory":"../../mcp-server/runtime","keep":"untouched"}',encoding='utf-8')

    def run_cli(self,configure=False,extra='',process='',listener='',env=None):
        if not PWSH: self.fail('PowerShell is required for these Windows installation tests')
        # CmdletBinding keeps ErrorAction/ErrorVariable semantics in query mocks.
        mocks=("function Get-Process { [CmdletBinding()] param([string[]]$Name) "+process+" };"
               "function Get-NetTCPConnection { [CmdletBinding()] param([string]$State,[int]$LocalPort) "+listener+" };")
        command=mocks+" & "+quote(self.mcp/'configure-runtime.ps1')+" -CphRoot "+quote(self.cph)
        if configure: command+=" -Configure -BurpStopped -BackupDirectory "+quote(self.base/'temp/backups')
        command+=' '+extra
        result=subprocess.run([PWSH,'-NoProfile','-NonInteractive','-Command',command],env=env or self.env,
                              cwd=TEMP,capture_output=True,encoding='utf-8',timeout=30)
        output=result.stdout+result.stderr
        for value in self.secrets.values(): self.assertNotIn(value,output)
        return result

    def test_default_is_read_only_and_detects_wrong_clone(self):
        self.initialize(); self.stale(); before=self.pointer.read_bytes()
        result=self.run_cli()
        self.assertEqual(1,result.returncode,result.stdout+result.stderr)
        self.assertFalse(json.loads(result.stdout)['pairingMatches'])
        self.assertEqual(before,self.pointer.read_bytes())
        self.assertFalse((self.base/'temp').exists())

    def test_configure_uses_selected_jar_and_preserves_everything_else(self):
        self.initialize(); self.stale()
        files={p:p.read_bytes() for p in (self.mcp/'runtime').iterdir()}
        before=self.pointer.read_bytes()
        result=self.run_cli(configure=True)
        self.assertEqual(0,result.returncode,result.stdout+result.stderr)
        report=json.loads(result.stdout); self.assertTrue(report['pairingMatches']); self.assertFalse(report['liveProcessVerified'])
        data=json.loads(self.pointer.read_text(encoding='utf-8'))
        self.assertEqual('../../mcp-server-latest/runtime',data['runtimeDirectory'])
        self.assertEqual('untouched',data['keep'])
        backups=list((self.base/'temp/backups').glob('*.before.*.json'))
        self.assertEqual(1,len(backups)); self.assertEqual(before,backups[0].read_bytes())
        for p,body in files.items(): self.assertEqual(body,p.read_bytes())
        result=self.run_cli(configure=True)
        self.assertEqual(0,result.returncode,result.stdout+result.stderr)
        self.assertEqual(1,len(list((self.base/'temp/backups').glob('*.before.*.json'))))

    def test_fresh_clone_can_pair_before_runtime_initialization(self):
        result=self.run_cli(configure=True)
        self.assertEqual(0,result.returncode,result.stdout+result.stderr)
        self.assertEqual('NOT_INITIALIZED',json.loads(result.stdout)['profileState'])
        self.assertFalse((self.mcp/'runtime').exists())

    def test_whole_installation_move_keeps_pairing(self):
        self.initialize(); self.assertEqual(0,self.run_cli(configure=True).returncode)
        moved=self.base.parent/'moved whole clone'; self.base.rename(moved)
        self.base=moved; self.mcp=moved/self.mcp.name; self.cph=moved/self.cph.name
        result=self.run_cli()
        self.assertEqual(0,result.returncode,result.stdout+result.stderr)
        self.assertTrue(json.loads(result.stdout)['pairingMatches'])

    def test_individual_folder_rename_requires_explicit_repair(self):
        self.initialize(); self.assertEqual(0,self.run_cli(configure=True).returncode)
        renamed=self.mcp.parent/'renamed again'; self.mcp.rename(renamed); self.mcp=renamed
        self.assertEqual(1,self.run_cli().returncode)
        result=self.run_cli(configure=True)
        self.assertEqual(0,result.returncode,result.stdout+result.stderr)
        self.assertEqual('../../renamed again/runtime',json.loads(self.pointer.read_text())['runtimeDirectory'])

    def test_running_burp_and_listeners_are_refused_without_change(self):
        self.initialize(); self.stale(); before=self.pointer.read_bytes()
        for process,listener,code in [('@{ Id=123 }','','BURP_MUST_BE_STOPPED'),
                                      ("Write-Error -Message 'query refused' -Category PermissionDenied",'','PROCESS_CHECK_FAILED'),
                                      ('','@{ OwningProcess=123 }','BURP_LISTENER_STILL_ACTIVE'),
                                      ('',"Write-Error -Message 'query refused' -Category PermissionDenied",'LISTENER_CHECK_FAILED')]:
            result=self.run_cli(True,process=process,listener=listener)
            self.assertEqual(1,result.returncode,result.stdout+result.stderr)
            self.assertEqual(code,json.loads(result.stdout)['code'])
            self.assertEqual(before,self.pointer.read_bytes())

    def test_missing_offline_confirmation_and_whatif_do_not_change_files(self):
        self.initialize(); self.stale(); before=self.pointer.read_bytes()
        result=self.run_cli(extra='-Configure')
        self.assertEqual('BURP_STOPPED_CONFIRMATION_REQUIRED',json.loads(result.stdout)['code'])
        result=self.run_cli(True,extra='-WhatIf')
        self.assertEqual(before,self.pointer.read_bytes())
        self.assertFalse((self.base/'temp').exists())

    def test_launch_override_is_reported_by_name_only_and_blocks_configuration(self):
        self.initialize(); self.stale(); before=self.pointer.read_bytes()
        env=dict(self.env,BURP_DIAG_CPH_TOKEN=self.secrets['cph'])
        result=self.run_cli(env=env)
        report=json.loads(result.stdout); self.assertTrue(report['launchOverridesPresent'])
        self.assertEqual(['BURP_DIAG_CPH_TOKEN'],report['launchOverrideNames'])
        result=self.run_cli(True,env=env)
        self.assertEqual('LAUNCH_ENVIRONMENT_OVERRIDE_PRESENT',json.loads(result.stdout)['code'])
        self.assertEqual(before,self.pointer.read_bytes())

    def test_malformed_credentials_and_legacy_redirect_are_not_repaired(self):
        self.initialize(); self.stale(); before=self.pointer.read_bytes()
        secrets=self.mcp/'runtime/operator-secrets.json'; original=secrets.read_bytes()
        secrets.write_text('{"cph":"'+self.secrets['cph']+'",broken}',encoding='utf-8')
        self.assertEqual('SELECTED_RUNTIME_PROFILE_NOT_READY',json.loads(self.run_cli(True).stdout)['code'])
        self.assertEqual(before,self.pointer.read_bytes())
        secrets.write_bytes(original)
        redirect=self.mcp/'runtime/cph-connection.json'; redirect.write_text('{"runtimeDirectory":"../../other/runtime"}')
        result=self.run_cli(True)
        self.assertEqual('MCP_LEGACY_REDIRECT_REQUIRES_REVIEW',json.loads(result.stdout)['code'])
        self.assertEqual(before,self.pointer.read_bytes())

    def test_non_review_jar_is_refused(self):
        self.stale(); before=self.pointer.read_bytes()
        with zipfile.ZipFile(self.jar,'w') as archive:
            archive.writestr('diagnostic-profile.properties','authorizationMode=QUICK\n')
        result=self.run_cli(True)
        self.assertEqual('SELECTED_MCP_REVIEW_PROFILE_REQUIRED',json.loads(result.stdout)['code'])
        self.assertEqual(before,self.pointer.read_bytes())

    def test_omitted_mode_uses_verified_jar_default_but_invalid_mode_is_rejected(self):
        self.initialize(); self.stale()
        settings=self.mcp/'runtime/settings.json'
        settings.write_text('{"schemaVersion":1}',encoding='utf-8')
        result=self.run_cli(True)
        self.assertEqual(0,result.returncode,result.stdout+result.stderr)
        self.assertEqual('READY',json.loads(result.stdout)['profileState'])
        self.assertEqual('{"schemaVersion":1}',settings.read_text())
        for value in ['review','UNKNOWN',None]:
            settings.write_text(json.dumps({'schemaVersion':1,'authorizationMode':value}),encoding='utf-8')
            result=self.run_cli()
            self.assertEqual(1,result.returncode,result.stdout+result.stderr)
            self.assertEqual('NOT_REVIEW',json.loads(result.stdout)['profileState'])

    def test_install_check_does_not_print_malformed_settings_content(self):
        self.initialize(); self.stale()
        (self.mcp/'runtime/settings.json').write_text('{"schemaVersion":1,"unexpected":"'+self.secrets['cph']+'",broken}',encoding='utf-8')
        result=subprocess.run([PWSH,'-NoProfile','-NonInteractive','-File',str(self.mcp/'check-install.ps1'),
                               '-CphRoot',str(self.cph)],env=self.env,cwd=TEMP,capture_output=True,encoding='utf-8',timeout=30)
        self.assertEqual(1,result.returncode,result.stdout+result.stderr)
        self.assertIn('input details withheld',result.stdout)
        for value in self.secrets.values(): self.assertNotIn(value,result.stdout+result.stderr)

if __name__=='__main__': unittest.main()
