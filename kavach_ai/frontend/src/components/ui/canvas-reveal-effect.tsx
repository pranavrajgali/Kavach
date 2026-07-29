import React, { useEffect, useRef } from "react";

interface CanvasRevealEffectProps {
  animationSpeed?: number;
  colors?: number[][]; // RGB arrays e.g. [[59, 130, 246]]
  dotSize?: number;
  gap?: number;
  showGradient?: boolean;
  containerClassName?: string;
}

export const CanvasRevealEffect: React.FC<CanvasRevealEffectProps> = ({
  animationSpeed = 0.4,
  colors = [[59, 130, 246]],
  dotSize = 1.5,
  gap = 15,
  showGradient = true,
  containerClassName = "",
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const mouseRef = useRef({ x: 0, y: 0, isOver: false });

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationId: number;
    let width = (canvas.width = container.clientWidth);
    let height = (canvas.height = container.clientHeight);

    const handleResize = () => {
      width = canvas.width = container.clientWidth;
      height = canvas.height = container.clientHeight;
    };

    window.addEventListener("resize", handleResize);

    const handleMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      mouseRef.current = {
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
        isOver: true,
      };
    };

    const handleMouseLeave = () => {
      mouseRef.current.isOver = false;
    };

    const handleMouseEnter = () => {
      mouseRef.current.isOver = true;
    };

    container.addEventListener("mousemove", handleMouseMove);
    container.addEventListener("mouseleave", handleMouseLeave);
    container.addEventListener("mouseenter", handleMouseEnter);

    let tick = 0;
    const render = () => {
      tick += animationSpeed * 0.05;
      ctx.clearRect(0, 0, width, height);

      const mouse = mouseRef.current;
      const [r, g, b] = colors[0] || [59, 130, 246];

      // Draw background reveal gradient
      if (mouse.isOver && showGradient) {
        const radialGrad = ctx.createRadialGradient(
          mouse.x,
          mouse.y,
          0,
          mouse.x,
          mouse.y,
          120
        );
        radialGrad.addColorStop(0, `rgba(${r}, ${g}, ${b}, 0.12)`);
        radialGrad.addColorStop(1, `rgba(${r}, ${g}, ${b}, 0)`);
        ctx.fillStyle = radialGrad;
        ctx.fillRect(0, 0, width, height);
      }

      // Draw the dots
      for (let x = gap / 2; x < width; x += gap) {
        for (let y = gap / 2; y < height; y += gap) {
          // Calculate distance
          const dx = x - mouse.x;
          const dy = y - mouse.y;
          const dist = Math.hypot(dx, dy);

          // Add a subtle wave/shimmer effect using sine wave over time
          const noise = Math.sin(x * 0.05 + y * 0.05 + tick) * 0.15;
          
          let opacity = 0.05 + Math.max(0, noise);
          let size = dotSize;
          let color = `rgba(161, 161, 170, ${opacity})`; // neutral gray dot

          if (mouse.isOver && dist < 125) {
            const factor = 1 - dist / 125; // 0 (far) to 1 (close)
            opacity = 0.08 + factor * 0.85;
            size = dotSize + factor * 0.8;
            color = `rgba(${r}, ${g}, ${b}, ${opacity})`;
          }

          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.arc(x, y, size, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      animationId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener("resize", handleResize);
      container.removeEventListener("mousemove", handleMouseMove);
      container.removeEventListener("mouseleave", handleMouseLeave);
      container.removeEventListener("mouseenter", handleMouseEnter);
      cancelAnimationFrame(animationId);
    };
  }, [colors, dotSize, gap, showGradient, animationSpeed]);

  return (
    <div
      ref={containerRef}
      className={`relative w-full h-full overflow-hidden ${containerClassName}`}
    >
      <canvas ref={canvasRef} className="block w-full h-full" />
    </div>
  );
};
