import React, { useState } from 'react';
import { X, Rocket, Shield, Globe } from 'lucide-react';

interface NewMissionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLaunch: (domain: string) => void;
}

export const NewMissionModal: React.FC<NewMissionModalProps> = ({ isOpen, onClose, onLaunch }) => {
  const [domain, setDomain] = useState('');
  const [isLaunching, setIsLaunching] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain) return;
    
    setIsLaunching(true);
    await onLaunch(domain);
    setIsLaunching(false);
    setDomain('');
    onClose();
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-surface-container border border-primary-fixed/30 w-full max-w-lg relative overflow-hidden glow-cyan">
        <div className="absolute top-0 left-0 w-full h-1 bg-primary-fixed opacity-50"></div>
        
        <div className="p-6 border-b border-outline-variant flex justify-between items-center">
          <div className="flex items-center gap-3">
            <Rocket className="text-primary-fixed" size={20} />
            <span className="font-label-caps text-headline-md text-primary-fixed tracking-widest">INITIALIZE NEW MISSION</span>
          </div>
          <button onClick={onClose} aria-label="Close" className="text-on-surface-variant hover:text-primary transition-colors">
            <X size={20} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-8 space-y-6">
          <div className="space-y-2">
            <label className="font-label-caps text-[10px] text-on-surface-variant flex items-center gap-2">
              <Globe size={12} /> TARGET DOMAIN
            </label>
            <input
              autoFocus
              type="text"
              placeholder="e.g. ginandjuice.shop"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="w-full bg-black border border-outline-variant p-4 text-primary font-code-sm text-code-sm focus:border-primary-fixed/50 outline-none transition-all placeholder:opacity-20"
            />
          </div>

          <div className="bg-primary-container/10 border border-primary-container/30 p-4 flex gap-4">
             <Shield className="text-primary-fixed shrink-0" size={20} />
             <p className="text-[11px] text-on-surface-variant leading-relaxed font-code-sm">
                Swarm will execute with <span className="text-primary-fixed font-bold">V5 AUTONOMOUS RUNTIME</span>. 
                Full-spectrum discovery, differential auth testing, and visual context mapping enabled.
             </p>
          </div>

          <div className="flex gap-4 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 py-3 border border-outline text-on-surface font-label-caps text-[11px] hover:bg-surface-variant transition-all"
            >
              ABORT
            </button>
            <button
              type="submit"
              disabled={!domain || isLaunching}
              className={`flex-1 py-3 bg-primary-fixed text-black font-label-caps text-[11px] glow-green hover:brightness-110 active:scale-95 transition-all flex items-center justify-center gap-2 ${(!domain || isLaunching) ? 'opacity-50 grayscale cursor-not-allowed' : ''}`}
            >
              {isLaunching ? 'DEPLOYING SWARM...' : 'LAUNCH MISSION'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
