import React, { useState, useRef } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { UploadCloud } from 'lucide-react';

export const UploadPanel: React.FC = () => {
  const { detonate } = useDetonation();
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith('.apk')) {
        detonate(file);
      }
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.name.endsWith('.apk')) {
        detonate(file);
      }
    }
  };

  const triggerFileInput = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="max-w-xl mx-auto my-16 text-center space-y-8">
      {/* Title Header */}
      <div>
        <h2 className="text-2xl font-bold text-foreground tracking-tight">
          Dynamic Sandbox Detonator
        </h2>
        <p className="text-sm text-muted-foreground mt-2 max-w-sm mx-auto leading-relaxed">
          Upload an Android APK to analyze code behaviors, instrumentation logs, and kernel sockets in real time.
        </p>
      </div>

      {/* Drag & Drop Card (Obsidian glass-morphism style) */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={triggerFileInput}
        className={`border border-dashed rounded-none p-10 cursor-pointer transition-all flex flex-col items-center justify-center space-y-4 ${
          isDragOver 
            ? 'border-primary bg-primary/5 shadow-[0_0_15px_rgba(59,130,246,0.15)] scale-[1.01]' 
            : 'border-muted hover:border-primary/50 bg-card/60 hover:bg-card/80 hover:shadow-[0_0_10px_rgba(255,255,255,0.02)]'
        }`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          accept=".apk"
          className="hidden"
        />

        <div className="p-4 rounded-none bg-background border border-border text-muted-foreground transition-all">
          <UploadCloud className="w-8 h-8" />
        </div>

        <div className="space-y-1">
          <p className="text-sm font-semibold text-foreground">
            Drag and drop your APK file here
          </p>
          <p className="text-xs text-muted-foreground">
            or click to browse local files
          </p>
        </div>

        <span className="text-[10px] uppercase font-bold tracking-wider text-muted-foreground px-2 py-1 bg-background/80 border border-border rounded-none">
          Support .apk binaries
        </span>
      </div>
    </div>
  );
};
export default UploadPanel;
