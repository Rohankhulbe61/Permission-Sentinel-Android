import { Link } from 'react-router-dom';
import { ShieldAlert, ArrowLeft, Home } from 'lucide-react';

export default function NotFound() {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '70vh',
      textAlign: 'center',
      padding: '24px'
    }}>
      <div style={{
        background: 'rgba(239, 68, 68, 0.12)',
        border: '1px solid rgba(239, 68, 68, 0.3)',
        borderRadius: '16px',
        padding: '20px',
        marginBottom: '20px',
        display: 'inline-flex'
      }}>
        <ShieldAlert size={48} style={{ color: '#ef4444' }} />
      </div>

      <h1 style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '8px' }}>
        404 — Route Not Found
      </h1>

      <p style={{ color: 'var(--text-muted)', maxWidth: '460px', marginBottom: '24px', fontSize: '0.95rem', lineHeight: '1.5' }}>
        The requested page or analysis route does not exist. It may have been moved, deleted, or entered incorrectly.
      </p>

      <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', justifyContent: 'center' }}>
        <Link to="/" className="btn btn-primary" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
          <Home size={16} />
          Return to Dashboard
        </Link>
        <button onClick={() => window.history.back()} className="btn btn-secondary" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
          <ArrowLeft size={16} />
          Go Back
        </button>
      </div>
    </div>
  );
}
