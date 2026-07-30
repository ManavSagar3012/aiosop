import React from 'react';
import { useParams, Link } from 'react-router-dom';
import { Card } from '../components/shared/Card';
import { EmptyState } from '../components/shared/EmptyState';
import { Skeleton } from '../components/shared/Skeleton';
import { useApiData } from '../hooks/useApiData';
import { ChevronLeft, Download, Shield, FileText, Printer } from 'lucide-react';

interface ReportData {
  report_id: string;
  markdown: string;
  html?: string;
  body_html?: string;
}

export const MissionReport: React.FC = () => {
  const { sessionId } = useParams<{ sessionId: string }>();
  const { data: report, loading } = useApiData<ReportData>(
    sessionId ? `/engagements/${sessionId}/report` : null
  );

  const handlePrint = () => {
    window.print();
  };

  if (loading) {
    return (
      <div className="flex flex-col gap-6 h-full overflow-hidden">
        <div className="flex justify-between items-center bg-surface-container-low p-4 border border-outline-variant">
          <div className="flex items-center gap-4">
            <Skeleton className="h-9 w-9" />
            <div className="flex flex-col gap-2">
              <Skeleton className="h-3 w-64" />
              <Skeleton className="h-5 w-40" />
            </div>
          </div>
          <div className="flex gap-2">
            <Skeleton className="h-9 w-32" />
            <Skeleton className="h-9 w-36" />
          </div>
        </div>
        <div className="flex-1 overflow-hidden bg-black/40 p-12 flex justify-center">
          <div className="max-w-4xl w-full flex flex-col gap-4">
            <Skeleton className="h-8 w-2/3" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-5/6" />
            <Skeleton className="h-40 w-full mt-6" />
            <Skeleton className="h-4 w-full mt-6" />
            <Skeleton className="h-4 w-3/4" />
          </div>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="h-full flex items-center justify-center">
        <Card title="ERROR" glow="red">
          <div className="p-6 text-center">
            <EmptyState
              icon={<Shield size={48} />}
              message="REPORT_NOT_FOUND"
              hint="The requested mission report could not be located in the vault."
            />
            <Link to="/" className="inline-block mt-4 px-6 py-2 bg-error text-white font-label-caps text-label-caps hover:brightness-110 transition-all">RETURN TO OVERVIEW</Link>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 h-full overflow-hidden">
      {/* Header */}
      <div className="flex justify-between items-center bg-surface-container-low p-4 border border-outline-variant">
        <div className="flex items-center gap-4">
          <Link to="/" className="p-2 hover:bg-surface-variant transition-colors border border-outline-variant">
            <ChevronLeft size={20} className="text-on-surface-variant" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
               <FileText size={16} className="text-primary-fixed" />
               <span className="font-code-sm text-[10px] text-on-surface-variant uppercase tracking-tighter">OFFENSIVE SECURITY ASSESSMENT REPORT</span>
            </div>
            <div className="font-headline-md text-[18px] text-on-surface">{report.report_id}</div>
          </div>
        </div>
        <div className="flex gap-2">
           <button className="flex items-center gap-2 px-4 py-2 bg-surface-variant border border-outline-variant text-[11px] font-label-caps hover:bg-surface-container-high transition-all">
              <Download size={14} /> EXPORT PDF
           </button>
           <button 
              onClick={handlePrint}
              className="flex items-center gap-2 px-4 py-2 bg-primary-fixed text-black border border-primary-fixed text-[11px] font-label-caps hover:brightness-110 transition-all font-bold"
           >
              <Printer size={14} /> PRINT REPORT
           </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar bg-black/40 p-12 flex justify-center">
        <div className="max-w-4xl w-full bg-surface-container-high p-20 shadow-[0_30px_60px_-12px_rgba(0,0,0,0.5)] border border-outline-variant relative min-h-[1100px]">
           {/* Decorative corner accents */}
           <div className="absolute top-0 left-0 w-8 h-8 border-t-2 border-l-2 border-primary-fixed/30"></div>
           <div className="absolute top-0 right-0 w-8 h-8 border-t-2 border-r-2 border-primary-fixed/30"></div>
           <div className="absolute bottom-0 left-0 w-8 h-8 border-b-2 border-l-2 border-primary-fixed/30"></div>
           <div className="absolute bottom-0 right-0 w-8 h-8 border-b-2 border-r-2 border-primary-fixed/30"></div>

           {/* Watermark */}
           <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 opacity-[0.02] rotate-[-45deg] pointer-events-none select-none">
              <div className="text-[140px] font-bold text-white whitespace-nowrap">AI-OSOP CONFIDENTIAL</div>
           </div>

           {/* Report Content */}
           <div className="relative z-10 text-on-surface">
              {(report.body_html || report.html) ? (
                <iframe
                  className="w-full min-h-[900px] border border-outline-variant bg-white"
                  title="Mission report content"
                  sandbox=""
                  referrerPolicy="no-referrer"
                  srcDoc={report.body_html || report.html || ''}
                />
              ) : (
                <pre className="whitespace-pre-wrap font-code-sm text-on-surface-variant text-[15px] leading-relaxed bg-black/40 p-10 border border-outline-variant">
                  {report.markdown}
                </pre>
              )}
           </div>
           
           {/* Signatures */}
           <div className="mt-32 grid grid-cols-2 gap-20">
              <div className="border-t border-outline-variant pt-4">
                 <div className="font-code-sm text-[12px] text-primary-fixed mb-1 uppercase">Automated Verification</div>
                 <div className="font-display text-[14px] italic opacity-60 font-light tracking-widest text-on-surface">AI-OSOP V6.5 Elite Kernel</div>
              </div>
              <div className="border-t border-outline-variant pt-4">
                 <div className="font-code-sm text-[12px] text-secondary-fixed mb-1 uppercase">Chain of Custody</div>
                 <div className="font-code-sm text-[10px] opacity-40 truncate">SIGNATURE: SHA256:{report.report_id.split('-')[1] || 'UNSET'}</div>
              </div>
           </div>
           <div className="mt-20 pt-8 border-t border-outline-variant flex justify-between items-center">
              <div className="flex items-center gap-4">
                 <img src="/logo.svg" alt="AI-OSOP" className="h-6 opacity-40 grayscale invert" />
                 <div className="h-4 w-px bg-outline-variant"></div>
                 <div className="text-[10px] text-on-surface-variant font-code-sm opacity-60">
                    GENERATED BY AI-OSOP V6.5 ELITE RUNTIME
                 </div>
              </div>
              <div className="text-[10px] text-on-surface-variant font-code-sm opacity-60">
                 PAGE 1 / 1
              </div>
           </div>
        </div>
      </div>
    </div>
  );
};
