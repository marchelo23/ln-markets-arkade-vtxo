import { useState, useEffect, useRef } from 'react';
import type { DiagnosticLine } from '../data/mockData';

interface Props {
  lines: DiagnosticLine[];
}

export default function LiveTerminal({ lines }: Props) {
  const [visibleLines, setVisibleLines] = useState<DiagnosticLine[]>([]);
  const [isComplete, setIsComplete] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [visibleLines]);

  // Simulate real-time logging
  useEffect(() => {
    let timeoutIds: number[] = [];
    setVisibleLines([]);
    setIsComplete(false);

    // Give a small initial delay
    const initialDelay = 300;

    lines.forEach((line, index) => {
      // Simulate slightly varied delays between 50ms and 200ms
      const delay = initialDelay + (index * 120) + (Math.random() * 80);
      
      const id = window.setTimeout(() => {
        setVisibleLines((prev) => [...prev, line]);
        if (index === lines.length - 1) {
          setIsComplete(true);
        }
      }, delay);
      
      timeoutIds.push(id);
    });

    return () => {
      timeoutIds.forEach(clearTimeout);
    };
  }, [lines]);

  return (
    <div className="terminal animate-fade-in">
      <div className="terminal-header">
        <span className="terminal-dot error"></span>
        <span className="terminal-dot warning"></span>
        <span className="terminal-dot success"></span>
        <span style={{ 
          marginLeft: '12px', 
          fontFamily: 'var(--font-mono)', 
          fontSize: '0.7rem',
          color: 'var(--on-surface-dim)' 
        }}>
          cve@arkade:~/verify$ ./cve_validate_vtxo
        </span>
      </div>

      <div className="terminal-body" ref={scrollRef}>
        {!isComplete && <div className="terminal-scanline"></div>}

        <div className="terminal-line">
          <span className="terminal-prompt">cve@arkade:~$</span> ./cve_validate_vtxo --txid 000000000000000000030f0f...
        </div>
        <div className="terminal-line" style={{ marginBottom: '16px' }}>
          Initializing cryptographic sub-systems... OK
        </div>

        {visibleLines.map((line, i) => (
          <div key={i} className={`terminal-line ${line.type}`}>
            {line.message && (
              <>
                <span style={{ color: 'var(--on-surface-dim)', marginRight: '16px' }}>
                  [{line.timestamp}]
                </span>
                {line.message}
              </>
            )}
            {!line.message && <br />}
          </div>
        ))}

        {isComplete && (
          <div className="terminal-line" style={{ marginTop: '16px' }}>
            <span className="terminal-prompt">cve@arkade:~$</span>
            <span className="terminal-cursor"></span>
          </div>
        )}
      </div>
    </div>
  );
}
