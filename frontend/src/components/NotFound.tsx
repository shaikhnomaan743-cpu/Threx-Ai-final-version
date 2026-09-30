import { useNavigate } from "react-router-dom";
import { AlertTriangle, ArrowLeft } from "lucide-react";
import { Button } from "./ui/Button";

export function NotFound() {
  const navigate = useNavigate();
  return (
    <div className="flex items-center justify-center h-[60vh]">
      <div className="text-center">
        <AlertTriangle className="w-16 h-16 text-[var(--color-text-muted)] mx-auto mb-6" />
        <h1 className="text-4xl font-light text-[var(--color-text-primary)] tracking-tight">404</h1>
        <p className="text-lg text-[var(--color-text-secondary)] mt-2">Page not found</p>
        <p className="text-sm text-[var(--color-text-muted)] mt-1">The requested route does not exist in this deployment.</p>
        <Button onClick={() => navigate("/")} className="mt-6" variant="primary">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Overview
        </Button>
      </div>
    </div>
  );
}
