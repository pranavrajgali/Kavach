"use client" 

export function ShiningText({ text }: { text: string }) {
  return (
    <h1 className="animate-pulse bg-[linear-gradient(110deg,#404040,35%,#fff,50%,#404040,75%,#404040)] bg-[length:200%_100%] bg-clip-text text-base font-regular text-transparent">
      {text}
    </h1>
  );
}

