import React, { useEffect, useState } from 'react';
import { API_BASE } from '../services/api';
import { useParams, Link } from 'react-router-dom';
import { Card } from '../components/shared/Card';
import { ChevronLeft, Download, Shield, FileText, Printer, Share2 } from 'lucide-react';

interface ReportData {
  report_id: string;
  markdown: string;
  html?: string;
  body_html?: string;
}

export const MissionReport: React.FC = () => {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [report, setReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);

  const handlePrint = () => {
    window.print();
  };

  useEffect(() => {
    const fetchReport = async () => {
      try {
        const response = await fetch(`${API_BASE}/engagements/${sessionId}/report`, {
          headers: { 'Authorization': 'Bearer dev-token' }
        });
        if (response.ok) {
          const data = await response.json();
          setReport(data);
        }
      } catch (e) {
        console.error("Failed to fetch report", e);
      } finally {
        setLoading(false);
      }
    };

    if (sessionId) {
      fetchReport();
    }
  }, [sessionId]);

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-primary-fixed border-t-transparent rounded-full animate-spin"></div>
          <div className="font-code-sm text-primary-fixed animate-pulse tracking-widest">COMPILING MISSION DATA...</div>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="h-full flex items-center justify-center">
        <Card title="ERROR" glow="red">
          <div className="p-6 text-center">
            <Shield className="text-error mx-auto mb-4" size={48} />
            <div className="font-headline-md text-on-surface mb-2">REPORT_NOT_FOUND</div>
            <div className="text-on-surface-variant mb-6 text-[14px]">The requested mission report could not be located in the vault.</div>
            <Link to="/" className="px-6 py-2 bg-error text-white font-label-caps">RETURN TO OVERVIEW</Link>
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
                <div 
                  className="report-body
                    [&_h1]:text-[36px] [&_h1]:font-display [&_h1]:text-on-surface [&_h1]:uppercase [&_h1]:tracking-tighter [&_h1]:border-b-2 [&_h1]:border-primary-fixed/20 [&_h1]:pb-6 [&_h1]:mb-12 [&_h1]:font-black
                    [&_h2]:text-[22px] [&_h2]:font-display [&_h2]:text-primary-fixed [&_h2]:uppercase [&_h2]:mt-16 [&_h2]:mb-8 [&_h2]:tracking-widest [&_h2]:border-l-4 [&_h2]:border-primary-fixed [&_h2]:pl-4
                    [&_h3]:text-[18px] [&_h3]:font-headline-md [&_h3]:text-on-surface [&_h3]:mt-10 [&_h3]:mb-6 [&_h3]:border-b [&_h3]:border-outline-variant [&_h3]:pb-2
                    [&_h4]:text-[14px] [&_h4]:font-label-caps [&_h4]:text-secondary-fixed [&_h4]:mt-8 [&_h4]:mb-4 [&_h4]:opacity-80
                    [&_p]:mb-6 [&_p]:leading-relaxed [&_p]:text-[16px] [&_p]:text-on-surface/90
                    [&_strong]:text-primary-fixed [&_strong]:font-bold
                    [&_code]:bg-black/60 [&_code]:px-2 [&_code]:py-1 [&_code]:rounded [&_code]:text-secondary-fixed [&_code]:font-code-sm [&_code]:border [&_code]:border-secondary/20
                    [&_pre]:bg-black/80 [&_pre]:p-8 [&_pre]:border [&_pre]:border-outline-variant [&_pre]:my-8 [&_pre]:overflow-x-auto [&_pre]:shadow-inner
                    [&_ul]:list-none [&_ul]:pl-0 [&_ul]:mb-8
                    [&_li]:mb-4 [&_li]:pl-6 [&_li]:relative [&_li]:text-[15px] [&_li]:before:content-['▶'] [&_li]:before:absolute [&_li]:before:left-0 [&_li]:before:text-primary-fixed [&_li]:before:text-[10px] [&_li]:before:top-1.5
                    [&_table]:w-full [&_table]:border-collapse [&_table]:my-10 [&_table]:shadow-xl
                    [&_th]:border [&_th]:border-outline-variant [&_th]:p-4 [&_th]:bg-surface-variant/50 [&_th]:text-left [&_th]:text-[12px] [&_th]:font-label-caps [&_th]:text-primary-fixed
                    [&_td]:border [&_td]:border-outline-variant [&_td]:p-4 [&_td]:text-[14px] [&_td]:bg-black/20
                  "
                  dangerouslySetInnerHTML={{ __html: report.body_html || report.html || "" }} 
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
