import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface MarkdownRendererProps {
  content: string;
  className?: string;
}

export const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({ content, className = '' }) => {
  if (!content) return null;

  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleCopyCode = (code: string, idx: number) => {
    navigator.clipboard.writeText(code);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const renderInline = (text: string): React.ReactNode => {
    // 1. Split code spans: `code`
    const codeSegments = text.split(/(`[^`]+`)/g);
    return codeSegments.map((segment, segIdx) => {
      if (segment.startsWith('`') && segment.endsWith('`') && segment.length > 2) {
        return (
          <code
            key={`inline-code-${segIdx}`}
            className="px-1.5 py-0.5 font-mono text-[11px] font-semibold bg-secondary/80 border border-border text-primary rounded-none"
          >
            {segment.slice(1, -1)}
          </code>
        );
      }

      // 2. Bold (**text**)
      const boldSegments = segment.split(/(\*\*[^*]+\*\*)/g);
      return boldSegments.map((bSeg, bIdx) => {
        if (bSeg.startsWith('**') && bSeg.endsWith('**') && bSeg.length > 4) {
          return (
            <strong key={`bold-${segIdx}-${bIdx}`} className="font-bold text-foreground">
              {bSeg.slice(2, -2)}
            </strong>
          );
        }

        // 3. Italic (*text* or _text_)
        const italicSegments = bSeg.split(/(\*[^*]+\*|_[^_]+_)/g);
        return italicSegments.map((iSeg, iIdx) => {
          if (
            (iSeg.startsWith('*') && iSeg.endsWith('*') && iSeg.length > 2) ||
            (iSeg.startsWith('_') && iSeg.endsWith('_') && iSeg.length > 2)
          ) {
            return (
              <em key={`italic-${segIdx}-${bIdx}-${iIdx}`} className="italic text-foreground/90">
                {iSeg.slice(1, -1)}
              </em>
            );
          }
          return iSeg;
        });
      });
    });
  };

  // Parse multi-line blocks
  const blocks: React.ReactNode[] = [];
  const lines = content.split('\n');
  let i = 0;
  let blockKey = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    // 1. Code Blocks (```lang ... ```)
    if (trimmed.startsWith('```')) {
      const lang = trimmed.slice(3).trim() || 'code';
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // Skip closing ```
      const codeString = codeLines.join('\n');
      const currentCodeIdx = blockKey++;

      blocks.push(
        <div key={`code-block-${currentCodeIdx}`} className="my-2.5 border border-border bg-black/70 overflow-hidden font-mono">
          <div className="flex items-center justify-between px-3 py-1 bg-secondary/50 border-b border-border text-[10px] text-muted-foreground uppercase font-bold tracking-wider">
            <span>{lang}</span>
            <button
              onClick={() => handleCopyCode(codeString, currentCodeIdx)}
              className="flex items-center gap-1 hover:text-foreground transition-all cursor-pointer"
            >
              {copiedIndex === currentCodeIdx ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" />
                  <span className="text-emerald-400">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>Copy</span>
                </>
              )}
            </button>
          </div>
          <pre className="p-3 text-[11px] overflow-x-auto whitespace-pre leading-relaxed text-emerald-400 font-mono">
            <code>{codeString}</code>
          </pre>
        </div>
      );
      continue;
    }

    // 2. Headings
    if (trimmed.startsWith('### ')) {
      blocks.push(
        <h3 key={`h3-${blockKey++}`} className="text-xs font-bold text-primary mt-3 mb-1.5 tracking-wide uppercase">
          {renderInline(trimmed.slice(4))}
        </h3>
      );
      i++;
      continue;
    }

    if (trimmed.startsWith('## ')) {
      blocks.push(
        <h2 key={`h2-${blockKey++}`} className="text-sm font-bold text-foreground mt-3.5 mb-1.5 border-b border-border/50 pb-1">
          {renderInline(trimmed.slice(3))}
        </h2>
      );
      i++;
      continue;
    }

    if (trimmed.startsWith('# ')) {
      blocks.push(
        <h1 key={`h1-${blockKey++}`} className="text-base font-bold text-foreground mt-4 mb-2">
          {renderInline(trimmed.slice(2))}
        </h1>
      );
      i++;
      continue;
    }

    if (trimmed.startsWith('#### ')) {
      blocks.push(
        <h4 key={`h4-${blockKey++}`} className="text-xs font-semibold text-foreground mt-2 mb-1">
          {renderInline(trimmed.slice(5))}
        </h4>
      );
      i++;
      continue;
    }

    // 3. Horizontal Rule
    if (trimmed === '---' || trimmed === '***') {
      blocks.push(<hr key={`hr-${blockKey++}`} className="border-border/60 my-3" />);
      i++;
      continue;
    }

    // 4. Blockquotes
    if (trimmed.startsWith('> ')) {
      blocks.push(
        <blockquote
          key={`quote-${blockKey++}`}
          className="border-l-2 border-primary/60 pl-3 my-2 text-muted-foreground italic text-xs"
        >
          {renderInline(trimmed.slice(2))}
        </blockquote>
      );
      i++;
      continue;
    }

    // 5. Unordered List Items
    if (trimmed.startsWith('* ') || trimmed.startsWith('- ')) {
      const listItems: React.ReactNode[] = [];
      while (i < lines.length && (lines[i].trim().startsWith('* ') || lines[i].trim().startsWith('- '))) {
        const itemText = lines[i].trim().slice(2);
        listItems.push(
          <li key={`li-${blockKey++}`} className="leading-relaxed">
            {renderInline(itemText)}
          </li>
        );
        i++;
      }
      blocks.push(
        <ul key={`ul-${blockKey++}`} className="list-disc list-inside space-y-1 my-2 text-xs text-foreground/90 pl-1">
          {listItems}
        </ul>
      );
      continue;
    }

    // 6. Ordered List Items (1. , 2. )
    if (/^\d+\.\s/.test(trimmed)) {
      const listItems: React.ReactNode[] = [];
      while (i < lines.length && /^\d+\.\s/.test(lines[i].trim())) {
        const itemText = lines[i].trim().replace(/^\d+\.\s/, '');
        listItems.push(
          <li key={`oli-${blockKey++}`} className="leading-relaxed">
            {renderInline(itemText)}
          </li>
        );
        i++;
      }
      blocks.push(
        <ol key={`ol-${blockKey++}`} className="list-decimal list-inside space-y-1 my-2 text-xs text-foreground/90 pl-1">
          {listItems}
        </ol>
      );
      continue;
    }

    // 7. Regular Paragraph (skip pure empty lines or render as spacing)
    if (trimmed === '') {
      i++;
      continue;
    }

    blocks.push(
      <p key={`p-${blockKey++}`} className="leading-relaxed my-1.5 text-xs text-foreground">
        {renderInline(line)}
      </p>
    );
    i++;
  }

  return <div className={`space-y-1 text-xs ${className}`}>{blocks}</div>;
};
