import { useEffect, useRef } from "react";

/** How many points make up the sphere, and how fast it turns (radians per second). */
const POINTS = 3200;
const TURN_SPEED = 0.12;
const TILT = 0.38;

type Rgb = [number, number, number];

/** A colour token from tokens.css, as numbers (so every colour stays in that one file). */
function token(name: string): Rgb {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const match = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(value);
  return match ? [parseInt(match[1], 16), parseInt(match[2], 16), parseInt(match[3], 16)] : [128, 128, 128];
}

/** Back to a CSS colour; the values always come from the tokens above, never from here. */
const css = (colour: Rgb) => "#" + colour.map((v) => Math.round(v).toString(16).padStart(2, "0")).join("");

const mix = (a: Rgb, b: Rgb, t: number): Rgb => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];

/** Points spread evenly over a sphere (a Fibonacci lattice), each nudged a little so it looks organic. */
function spherePoints(count: number): Float32Array {
  const points = new Float32Array(count * 3);
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < count; i++) {
    const y = 1 - (i / (count - 1)) * 2;
    const ring = Math.sqrt(1 - y * y);
    const r = 1 + (Math.random() - 0.5) * 0.06;
    points[i * 3] = Math.cos(golden * i) * ring * r;
    points[i * 3 + 1] = y * r;
    points[i * 3 + 2] = Math.sin(golden * i) * ring * r;
  }
  return points;
}

/**
 * The front door's live "signal orb": a slowly turning sphere of particles, drawn on a canvas.
 * Purely decorative (hidden from screen readers). It draws one still frame when the visitor asks
 * for reduced motion, stops while the tab is hidden, and leans a little towards the pointer.
 */
export function SignalOrb() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext("2d");
    if (!canvas || !context) {
      return;
    }
    const core = token("--color-orb-core");
    const light = token("--color-orb-light");
    const rim = token("--color-orb-rim");
    const points = spherePoints(POINTS);
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let angle = 0.6;
    let lean = 0;
    let leanTarget = 0;
    let frame = 0;
    let last = performance.now();

    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(canvas.clientWidth * ratio);
      canvas.height = Math.round(canvas.clientHeight * ratio);
    };

    const draw = () => {
      const { width, height } = canvas;
      context.clearRect(0, 0, width, height);
      const radius = Math.min(width, height) * 0.42;
      const cx = width / 2;
      const cy = height / 2;
      const dot = Math.max(1.2, width / 600);
      const [sinA, cosA] = [Math.sin(angle), Math.cos(angle)];
      const tilt = TILT + lean;
      const [sinT, cosT] = [Math.sin(tilt), Math.cos(tilt)];
      for (let i = 0; i < POINTS; i++) {
        const x0 = points[i * 3];
        const y0 = points[i * 3 + 1];
        const z0 = points[i * 3 + 2];
        // Turn around the vertical axis, then tip towards the viewer.
        const x = x0 * cosA + z0 * sinA;
        const z1 = -x0 * sinA + z0 * cosA;
        const y = y0 * cosT - z1 * sinT;
        const z = y0 * sinT + z1 * cosT;
        const depth = (z + 1) / 2; // 0 at the back, 1 at the front
        const perspective = 3 / (3 - z);
        const edge = 1 - Math.abs(z); // 1 on the outline
        let colour = mix(core, light, depth * depth);
        if (edge > 0.8) {
          colour = mix(colour, rim, (edge - 0.8) * 2.5);
        }
        context.globalAlpha = 0.1 + depth * 0.6;
        context.fillStyle = css(colour);
        const size = dot * (0.7 + depth * 1.6);
        context.fillRect(cx + x * radius * perspective, cy + y * radius * perspective, size, size);
      }
      context.globalAlpha = 1;
    };

    const tick = (now: number) => {
      const seconds = Math.min((now - last) / 1000, 0.1);
      last = now;
      angle += TURN_SPEED * seconds;
      lean += (leanTarget - lean) * Math.min(seconds * 3, 1);
      draw();
      frame = requestAnimationFrame(tick);
    };

    const start = () => {
      cancelAnimationFrame(frame);
      if (still || document.hidden) {
        draw();
        return;
      }
      last = performance.now();
      frame = requestAnimationFrame(tick);
    };

    const onPointer = (event: PointerEvent) => {
      leanTarget = (event.clientY / window.innerHeight - 0.5) * 0.3;
    };

    // Resizing a canvas wipes it, so draw again at once (otherwise a still orb would vanish).
    const observer = new ResizeObserver(() => {
      resize();
      draw();
    });
    observer.observe(canvas);
    start();
    document.addEventListener("visibilitychange", start);
    window.addEventListener("pointermove", onPointer);
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      document.removeEventListener("visibilitychange", start);
      window.removeEventListener("pointermove", onPointer);
    };
  }, []);

  return <canvas ref={canvasRef} className="orb" aria-hidden="true" />;
}
