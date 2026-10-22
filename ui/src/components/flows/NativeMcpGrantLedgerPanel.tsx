import { useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import { readNativeMcpGrantLedger, readNativeMcpOrphanSuspects, requestNativeWorkerRecoveryIntent, type NativeMcpGrantLedger, type NativeMcpOrphanSuspects } from '../../services/nativeMcpGrantLedger';

export interface NativeMcpGrantLedgerPanelProps {
  flowId:string;
  engagementId:string;
  revision:number;
  flowStatus:string;
  authorizationId?:string|null;
}

/** Actual 0029 durable grant history only. No raw grants or execution controls. */
export function NativeMcpGrantLedgerPanel({
  flowId,engagementId,revision,flowStatus,authorizationId,
}:NativeMcpGrantLedgerPanelProps){
  const [actor,setActor]=useState(()=>currentOperator());
  const [ledger,setLedger]=useState<NativeMcpGrantLedger|null>(null);
  const [suspects,setSuspects]=useState<NativeMcpOrphanSuspects|null>(null);
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState('');
  const [recoveryGrant,setRecoveryGrant]=useState<string|null>(null);
  const [recoveryChecked,setRecoveryChecked]=useState(false);
  const version=useRef(0);
  const eligible=!!authorizationId&&['pending','running'].includes(flowStatus)
    &&['operator','senior_operator'].includes(actor?.role??'');

  useEffect(()=>{
    ++version.current;setLedger(null);setSuspects(null);setBusy(false);setMessage('');setRecoveryGrant(null);setRecoveryChecked(false);
    return()=>{++version.current;};
  },[flowId,engagementId,revision,flowStatus,authorizationId]);
  useEffect(()=>subscribeOperator(next=>{
    ++version.current;setLedger(null);setSuspects(null);setBusy(false);setActor(next);setRecoveryGrant(null);setRecoveryChecked(false);
    setMessage('Operator changed: native redemption status requires fresh signed readback.');
  }),[]);

  async function refresh(){
    if(!eligible||busy||!authorizationId)return;
    const run=++version.current;setBusy(true);setLedger(null);setSuspects(null);setMessage('');
    try{
      const read=await readNativeMcpGrantLedger(engagementId,flowId,revision,authorizationId);
      if(version.current===run)setLedger(read);
    }catch{
      if(version.current===run)setMessage('Signed native grant status UNKNOWN or unavailable. No native execution may be inferred.');
    }finally{
      if(version.current===run)setBusy(false);
    }
  }

  async function readSuspects(){
    if(!eligible||busy||!authorizationId)return;
    const run=++version.current;
    setBusy(true);setSuspects(null);setMessage('');
    try{
      const result=await readNativeMcpOrphanSuspects(
        engagementId,flowId,revision,authorizationId,60,20,
      );
      if(version.current===run)setSuspects(result);
    }catch{
      if(version.current===run)setMessage('Supervisor SUSPECT readback UNKNOWN or unavailable. No process death, cleanup, or recovery may be inferred.');
    }finally{
      if(version.current===run)setBusy(false);
    }
  }

  async function requestRecovery(grantId:string, supervisorRevision:number){
    if(!eligible||busy||!recoveryChecked||recoveryGrant!==grantId||!authorizationId)return;
    const run=++version.current;setBusy(true);setMessage('');setLedger(null);setSuspects(null);
    try{
      await requestNativeWorkerRecoveryIntent(
        engagementId,flowId,revision,authorizationId,grantId,supervisorRevision,
      );
      if(run===version.current)setMessage('Metadata-only recovery intent recorded. Supervisor cleanup is NOT confirmed; refresh separately. UNKNOWN must not be replayed.');
    }catch{
      if(run===version.current)setMessage('Recovery intent outcome UNKNOWN. Read back; do not retry automatically.');
    }finally{
      if(run===version.current){setBusy(false);setRecoveryGrant(null);setRecoveryChecked(false);}
    }
  }

  return <Card title="Native MCP grants — durable history only">
    <div className="space-y-2 text-xs" aria-label="Native MCP grant ledger readback">
      <p>Read the signed Flow's PostgreSQL one-use grant records. A redeemed grant confirms native
        admission only for the inert authority_status diagnostic; it never establishes a scan,
        exploit, independently verified target effect, provider trust or final report release.
        There is no approval, signing, token download, dispatch, retry or remote tool control here.</p>
      <section aria-label="Native worker SUSPECTS only" className="space-y-2 border border-outline p-3">
        <strong>READ ONLY — SUSPECT / UNVERIFIED native workers</strong>
        <p>The time since a supervisor's last signed state transition is NOT a heartbeat.
          A stale record cannot prove an orphan, running process, shutdown or cleanup.
          This list never runs Docker, relaunches a worker, replays an Action or marks REAPED.
          It contains no grant IDs, worker IDs, container IDs, paths, credentials or hashes.</p>
        <button type="button" disabled={!eligible||busy} onClick={()=>void readSuspects()}
          className="border border-outline px-3 py-2 disabled:opacity-40">
          {busy?'READING OWNER SUSPECTS…':'READ ORPHAN SUSPECTS (GET ONLY)'}
        </button>
        {suspects&&<div role="status" className="space-y-2">
          <p>{suspects.count} historical SUSPECT record(s); no independent process
            liveness verification and no automatic reaping.</p>
          {suspects.candidates.length===0&&<p>No stale signed supervisor transitions were returned for this owner and Flow.</p>}
          {suspects.candidates.map(item=><div key={item.ordinal} className="border border-outline p-2">
            <p>Candidate {item.ordinal} · {item.classification==='pending_independent_recovery'
              ? 'PENDING INDEPENDENT RECOVERY'
              : 'SUSPECTED ORPHAN — UNVERIFIED'}</p>
            <p>Last signed state: {item.state}; grant status: {item.grant_status};
              age since transition: {item.age_since_last_signed_transition_seconds} seconds.</p>
            <p>Container destruction NOT verified. No execution replay authorized.
              Use the separate owner grant ledger for metadata-only recovery intent
              on an already UNKNOWN/terminating revision; that request never cleans up a worker.</p>
          </div>)}
        </div>}
      </section>
      <button type="button" disabled={!eligible||busy} onClick={()=>void refresh()}
        className="border border-outline px-3 py-2 disabled:opacity-40">
        {busy?'READING SIGNED GRANT HISTORY…':'READ NATIVE GRANT LEDGER (GET ONLY)'}
      </button>
      {message&&<p role="alert">{message}</p>}
      {ledger&&<div role="status" className="space-y-2">
        <p>Flow revision {ledger.flow_revision} · signed ROE version {ledger.authorization_version}.
          Independently verified target effect: NO. Historical grant status is not live permission.</p>
        {ledger.grants.length===0&&<p>No native grant was issued under this current signed Flow revision.</p>}
        {ledger.grants.map(item=><div key={item.grant_id} className="border border-outline p-2">
          <p><strong>{item.server_id}</strong> · {item.tool_name} · {item.status.toUpperCase()}</p>
          <p>Action {item.action_id} · request {item.request_id}</p>
          <p>Expires {new Date(item.expires_at*1000).toISOString()} · no automatic retry</p>
          <p>{item.reviewed_resource_bound
            ? (item.resource_bytes_checked_at_redemption
              ? 'Reviewed original resource bytes: integrity checked at historical redemption (untrusted data; not staged or executed).'
              : 'Reviewed resource digest bound at issuance; no redeemed original-byte confirmation.')
            : 'No reviewed resource digest attached; no resource staging or byte use claimed.'}</p>
          <p>{item.original_resource_bytes_offered_once
            ? 'Original reviewed resource bytes: offered exactly once by the durable source. Worker receipt, filesystem staging and target effects are NOT independently confirmed; ambiguous ACK must not be retried.'
            : 'No durable original-byte offer recorded. Native worker receipt or resource staging cannot be inferred.'}</p>
          <p>{item.approved_folder_staging_bound
            ? 'Original Task-pinned 0026 folder assignments matched the durable one-time source offer.'
            : 'No Task-pinned folder staging authorization recorded.'}</p>
          <p>{item.worker_stage_receipt_reported
            ? 'Separately Ed25519-signed worker stage readback REPORTED and durably recorded (worker testimony, not independent OS sandbox attestation or verified target effects).'
            : 'No durable independently keyed worker stage-readback testimony recorded; UNKNOWN must not be retried.'}</p>
          <p>{item.supervisor_lifecycle_observed
            ? `Independent container supervisor lifecycle: ${item.supervisor_state}. ${item.supervisor_cleanup_observed
              ? 'Owned container teardown recorded by the separately trusted supervisor; this does not attest target effects.'
              : item.supervisor_recovery_required
                ? 'Recovery required: supervised outcome is UNKNOWN; do not retry the original Action.'
                : 'Container lifecycle is not yet independently confirmed cleaned up.'}`
            : 'No independently recorded container supervisor lifecycle. Worker-signed receipts do not prove isolation, cleanup, or target effects.'}</p>
          {item.supervisor_recovery_intent_pending&&<p>Operator recovery review request was durably recorded for this exact supervisor revision. It does not re-run a worker, settle UNKNOWN, or establish cleanup.</p>}
          {item.supervisor_revision!==null&&['unknown','terminating'].includes(item.supervisor_state??'')&&<div>
            <label className="block"><input type="checkbox" checked={recoveryGrant===item.grant_id&&recoveryChecked}
              onChange={e=>{setRecoveryGrant(e.target.checked?item.grant_id:null);setRecoveryChecked(e.target.checked);}} />
              I explicitly request metadata-only recovery review. No worker relaunch, native replay or verified cleanup.</label>
            <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
              disabled={!eligible||busy||!recoveryChecked||recoveryGrant!==item.grant_id}
              onClick={()=>void requestRecovery(item.grant_id,item.supervisor_revision!)}>
              RECORD RECOVERY INTENT (NO EXECUTION)
            </button>
          </div>}
        </div>)}
      </div>}
    </div>
  </Card>;
}
