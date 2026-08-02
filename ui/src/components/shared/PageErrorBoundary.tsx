import React from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface Props {
  children: React.ReactNode;
  pageName?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class PageErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full min-h-[400px] p-12 text-center bg-surface-container-low border border-outline-variant/50">
          <AlertTriangle size={36} className="text-error mb-4 opacity-70" />
          <h2 className="font-label-caps text-label-caps text-error mb-2 uppercase tracking-wider">
            {this.props.pageName || 'Page'} Render Error
          </h2>
          <p className="font-code-sm text-[12px] text-on-surface-variant/70 max-w-md mb-6 leading-relaxed">
            {this.state.error?.message || 'An unexpected error occurred while rendering this page.'}
          </p>
          <button
            onClick={this.handleReset}
            className="flex items-center gap-2 px-6 py-2.5 border border-error text-error font-label-caps text-label-caps hover:bg-error/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-error transition-all"
          >
            <RotateCcw size={14} /> RETRY
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
