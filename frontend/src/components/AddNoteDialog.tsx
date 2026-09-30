import { useState, useRef, useEffect } from "react";
import { X, MessageSquare } from "lucide-react";
import { Button } from "./ui/Button";

interface AddNoteDialogProps {
  open: boolean;
  onClose: () => void;
  onSave: (note: string) => void;
  threatId: string;
}

export function AddNoteDialog({ open, onClose, onSave, threatId }: AddNoteDialogProps) {
  const [note, setNote] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (open) {
      setNote("");
      setTimeout(() => textareaRef.current?.focus(), 50);
    }
  }, [open]);

  const handleSave = () => {
    if (note.trim()) {
      onSave(note.trim());
      onClose();
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[90] flex items-center justify-center" onClick={onClose}>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" />
      <div
        className="relative bg-[var(--color-bg-elevated-1)] border border-[var(--color-border-card)] rounded-[8px] w-full max-w-md shadow-2xl animate-fade-in"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-4 border-b border-[var(--color-border-card)] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MessageSquare className="w-4 h-4 text-[var(--color-accent-cyan)]" />
            <h3 className="text-sm font-medium text-[var(--color-text-primary)]">Add Analyst Note</h3>
          </div>
          <button onClick={onClose} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] p-1" aria-label="Close dialog">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          <div>
            <label className="block text-xs text-[var(--color-text-muted)] mb-1">Threat ID: {threatId}</label>
            <textarea
              ref={textareaRef}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Enter analyst note..."
              rows={4}
              className="w-full bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-[6px] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-accent-cyan)] focus:ring-1 focus:ring-[var(--color-accent-cyan)] resize-none"
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
            <Button variant="primary" size="sm" onClick={handleSave} disabled={!note.trim()}>Save Note</Button>
          </div>
        </div>
      </div>
    </div>
  );
}
