import { EmailScannerPanel } from './EmailScannerPanel';

export function EmailScannerView() {
  return (
    <div className="flex h-full min-h-0 flex-1 flex-col overflow-hidden bg-slate-900">
      <div className="global-scroll min-h-0 flex-1 overflow-y-auto px-4 pb-8 pt-4 sm:px-6 sm:pt-6 xl:px-8 xl:pt-8">
        <EmailScannerPanel />
      </div>
    </div>
  );
}
