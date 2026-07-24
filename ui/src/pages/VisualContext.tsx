import React from 'react';
import { Card } from '../components/shared/Card';
import { EmptyState } from '../components/shared/EmptyState';
import { Eye } from 'lucide-react';

/**
 * Visual Context page.
 *
 * Previously this page contained entirely hardcoded mock data (fake active
 * elements, fake agent observations, an Unsplash placeholder image, and
 * hardcoded confidence values). All mock content has been removed. The page
 * now shows an honest empty state until a real visual-context API endpoint
 * is wired.
 *
 * The backend has a VisualContextAgent (src/ai_osop/agents/visual_agent.py)
 * that captures screenshots and DOM analysis. To wire this page:
 * 1. Add GET /engagements/{id}/visual-context endpoint to the API
 * 2. Fetch from this page using the Archetype B pattern (useCallback + useEffect)
 * 3. Render the real screenshot + DOM elements + agent observations
 */
export const VisualContext: React.FC = () => {
  return (
    <div className="flex flex-col items-center justify-center min-h-[400px] bg-surface-container border border-outline-variant p-8 rounded-sm">
      <EmptyState
        message="Visual context data is not yet available."
        icon={<Eye size={48} />}
        hint="This page will display screenshots, DOM analysis, and visual agent observations once the visual-context API endpoint is wired."
      />
    </div>
  );
};
