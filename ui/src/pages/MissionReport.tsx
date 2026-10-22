import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ChevronLeft, Download, FileText, Printer, Shield, RefreshCw } from 'lucide-react';
import { API_BASE, authHeaders } from '../services/api';
import { Card } from '../components/shared/Card';

export type ReportAvailability = 'limited_verified_summary' | 'no_verified_evidence';

export interface PrintableMissionReport {
  report_id: string;
  availability: ReportAvailability;
  markdown: string;
  verified_record_count: number;
}

const MAX_PRINTABLE_CHARACTERS = 32_000;
const GENERIC_REPORT_ERROR = 'Could not load the engagement summary. Try again.';
const SAFE_REPORT_MESSAGES = new Set([
  'The report service returned an invalid summary.',
  'Select a valid engagement to view its evidence summary.',
  'Report access denied. Check your operator authorization.',
  'This engagement is not available to your account.',
  'Verified evidence is temporarily unavailable. Try again later.',
  GENERIC_REPORT_ERROR,
]);

/** Never reflect fetch/JSON parser exceptions, which may contain response snippets. */
export function reportFetchErrorMessage(reason: unknown): string {
  return reason instanceof Error && SAFE_REPORT_MESSAGES.has(reason.message)
    ? reason.message
    : GENERIC_REPORT_ERROR;
}

/** Reject unexpected responses instead of interpreting arbitrary HTML or report drafts. */
export function parsePrintableMissionReport(value: unknown): PrintableMissionReport {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('The report service returned an invalid summary.');
  }
  const report = value as Record<string, unknown>;
  const availability = report.availability;
  const count = report.verified_record_count;
  if (
    (availability !== 'limited_verified_summary' && availability !== 'no_verified_evidence')
    || typeof report.report_id !== 'string'
    || !/^summary-[a-f0-9]{64}$/.test(report.report_id)
    || typeof report.markdown !== 'string'
    || !report.markdown.trim()
    || report.markdown.length > MAX_PRINTABLE_CHARACTERS
    || typeof count !== 'number'
    || !Number.isSafeInteger(count)
    || count < 0
    || count > 200
    || (availability === 'no_verified_evidence' && count !== 0)
    || (availability === 'limited_verified_summary' && count === 0)
  ) {
    throw new Error('The report service returned an invalid summary.');
  }
  return {
    report_id: report.report_id,
    availability,
    markdown: report.markdown,
    verified_record_count: count,
  };
}

/** Uses only the API's authenticated, bounded summary. Never fetches arbitrary URLs. */
export async function fetchMissionReport(
  sessionId: string,
  signal?: AbortSignal,
): Promise<PrintableMissionReport> {
  if (!sessionId || !/^[a-zA-Z0-9_-]{1,96}$/.test(sessionId)) {
    throw new Error('Select a valid engagement to view its evidence summary.');
  }
  const response = await fetch(
    `${API_BASE}/engagements/${encodeURIComponent(sessionId)}/report`,
    {
      headers: authHeaders({ Accept: 'application/json' }),
      cache: 'no-store',
      signal,
    },
  );
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new Error('Report access denied. Check your operator authorization.');
    }
    if (response.status === 404) {
      throw new Error('This engagement is not available to your account.');
    }
    if (response.status === 503) {
      throw new Error('Verified evidence is temporarily unavailable. Try again later.');
    }
    throw new Error('Could not load the engagement summary. Try again.');
  }
  return parsePrintableMissionReport(await response.json() as unknown);
}

/** The browser provides the print/PDF destination picker; no fake PDF download. */
export function openMissionReportPrintDialog(): void {
  window.print();
}

export const MissionReportDocument: React.FC<{
  report: PrintableMissionReport;
  sessionId: string;
}> = ({ report, sessionId }) => {
  const hasQualifiedEvidence = report.availability === 'limited_verified_summary';
  return (
    <article
      id="mission-report-print-area"
      aria-label="Printable engagement evidence summary"
      className="max-w-4xl w-full bg-surface-container-high p-8 md:p-12 shadow-xl border border-outline-variant relative text-on-surface"
    >
      <header className="border-b border-outline-variant pb-6 mb-8">
        <p className="font-label-caps text-[11px] tracking-widest text-on-surface-variant">
          AI-OSOP · Engagement evidence summary
        </p>
        <h1 className="font-headline-md text-[25px] mt-3 break-words">
          Engagement {sessionId}
        </h1>
        <p className="font-code-sm text-[11px] text-on-surface-variant mt-3 break-all">
          Summary reference (not a signature): {report.report_id}
        </p>
      </header>

      <div
        role="status"
        aria-live="polite"
        className="bg-surface-container-low border-l-4 border-primary-fixed p-5 mb-8"
      >
        <h2 className="font-headline-md text-[17px]">
          {hasQualifiedEvidence ? 'Limited evidence summary available' : 'No verified evidence available'}
        </h2>
        <p className="text-[14px] text-on-surface-variant mt-2">
          {hasQualifiedEvidence
            ? `The graph contains ${report.verified_record_count} validated record${report.verified_record_count === 1 ? '' : 's'} with stored evidence. This does not independently establish exploit success.`
            : 'No qualifying verified records were available. This does not mean the engagement is secure or free of findings.'}
        </p>
      </div>

      <section aria-label="Evidence summary text">
        <h2 className="font-headline-md text-[18px] mb-4">Available summary</h2>
        <pre className="whitespace-pre-wrap break-words font-code-sm text-on-surface-variant text-[14px] leading-relaxed bg-black/20 p-6 border border-outline-variant">
          {report.markdown}
        </pre>
      </section>

      <footer className="mt-10 border-t border-outline-variant pt-5 text-[12px] text-on-surface-variant">
        This is an automatically retrieved summary, not an approved or signed final
        security report. Its content has not been independently reverified by this
        page; no cryptographic signature is asserted.
      </footer>
    </article>
  );
};

/** Print only the safely escaped React text, without surrounding console chrome. */
const REPORT_PRINT_STYLES = `
  @media print {
    @page { margin: 15mm; }
    html, body, #root { height: auto !important; overflow: visible !important; }
    body * { visibility: hidden !important; }
    #mission-report-print-area, #mission-report-print-area * {
      visibility: visible !important;
    }
    #mission-report-print-area {
      position: absolute !important;
      left: 0 !important;
      top: 0 !important;
      width: 100% !important;
      padding: 0 !important;
      margin: 0 !important;
      min-height: 0 !important;
      background: white !important;
      color: black !important;
      border: 0 !important;
      box-shadow: none !important;
    }
    #mission-report-print-area * {
      color: black !important;
      border-color: #aaa !important;
      background: white !important;
      overflow-wrap: anywhere !important;
    }
    #mission-report-print-area pre {
      white-space: pre-wrap !important;
      overflow: visible !important;
      font-size: 11pt !important;
    }
    .mission-report-no-print { display: none !important; }
  }
`;

export const MissionReport: React.FC = () => {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [report, setReport] = useState<PrintableMissionReport | null>(null);
  const [reportSessionId, setReportSessionId] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadCount, setReloadCount] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let current = true;
    setLoading(true);
    setError(null);
    setReport(null);
    setReportSessionId(sessionId);
    if (!sessionId) {
      setError('Select an engagement to view its evidence summary.');
      setLoading(false);
      return () => { controller.abort(); };
    }

    void fetchMissionReport(sessionId, controller.signal)
      .then((loaded) => {
        if (current) setReport(loaded);
      })
      .catch((reason: unknown) => {
        if (current && !controller.signal.aborted) {
          setError(reportFetchErrorMessage(reason));
        }
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
      controller.abort();
    };
  }, [sessionId, reloadCount]);

  // Printable responses contain no HTML, including legacy body_html/html fields.
  if (loading || reportSessionId !== sessionId) {
    return (
      <div className="h-full flex items-center justify-center" role="status" aria-live="polite">
        <div className="flex flex-col items-center gap-4">
          <div aria-hidden="true" className="w-12 h-12 border-4 border-primary-fixed border-t-transparent rounded-full animate-spin" />
          <div className="font-code-sm text-primary-fixed animate-pulse tracking-widest">LOADING EVIDENCE SUMMARY...</div>
        </div>
      </div>
    );
  }
  if (!report) {
    return (
      <div className="h-full flex items-center justify-center p-6">
        <Card title="Report unavailable" glow="red">
          <div className="p-6 text-center space-y-5">
            <Shield aria-hidden="true" className="text-error mx-auto" size={44} />
            <p role="alert" className="text-on-surface-variant text-[14px]">
              {error ?? 'No validated engagement summary is available.'}
            </p>
            <button
              type="button"
              onClick={() => setReloadCount((n) => n + 1)}
              className="inline-flex gap-2 items-center px-4 py-2 bg-surface-variant border border-outline-variant font-label-caps"
            >
              <RefreshCw size={15} aria-hidden="true" /> RETRY
            </button>
            <Link to="/" className="block text-primary-fixed text-[13px]">Return to overview</Link>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 h-full overflow-hidden">
      <style>{REPORT_PRINT_STYLES}</style>
      <div className="mission-report-no-print flex flex-wrap justify-between gap-4 items-center bg-surface-container-low p-4 border border-outline-variant">
        <div className="flex items-center gap-4 min-w-0">
          <Link to="/" aria-label="Back to overview" className="p-2 hover:bg-surface-variant transition-colors border border-outline-variant">
            <ChevronLeft size={20} aria-hidden="true" className="text-on-surface-variant" />
          </Link>
          <FileText size={18} aria-hidden="true" className="text-primary-fixed" />
          <div className="min-w-0">
            <div className="font-headline-md text-[18px]">Engagement evidence summary</div>
            <div className="font-code-sm text-[11px] text-on-surface-variant truncate">
              {sessionId}
            </div>
          </div>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button
            type="button"
            onClick={openMissionReportPrintDialog}
            title="Choose Save as PDF in the browser print dialog"
            className="inline-flex items-center gap-2 px-4 py-2 bg-surface-variant border border-outline-variant text-[11px] font-label-caps hover:bg-surface-container-high"
          >
            <Download size={14} aria-hidden="true" /> SAVE AS PDF
          </button>
          <button
            type="button"
            onClick={openMissionReportPrintDialog}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary-fixed text-black border border-primary-fixed text-[11px] font-label-caps hover:brightness-110 font-bold"
          >
            <Printer size={14} aria-hidden="true" /> PRINT SUMMARY
          </button>
        </div>
      </div>
      <p className="mission-report-no-print text-on-surface-variant text-[12px] px-4">
        PDF export opens your browser print dialog. Select “Save as PDF” as the destination; this is not a signed report.
      </p>
      <div className="flex-1 overflow-y-auto p-4 md:p-10 bg-black/40 flex justify-center">
        <MissionReportDocument report={report} sessionId={sessionId ?? ''} />
      </div>
    </div>
  );
};
