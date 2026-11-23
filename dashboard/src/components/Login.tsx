import { ArrowDown, Radar, ShieldCheck, Sparkles } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";

import { api, errorText } from "../api";
import type { User } from "../types";
import { FrontSections } from "./FrontSections";
import { SignalOrb } from "./SignalOrb";

export function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Only the public demo offers the button; if the server cannot say, the page simply doesn't show it.
  const [demoLogin, setDemoLogin] = useState(false);

  useEffect(() => {
    let current = true;
    api
      .authOptions()
      .then((options) => current && setDemoLogin(options.demoLogin))
      .catch(() => {});
    return () => {
      current = false;
    };
  }, []);

  async function attempt(login: () => Promise<User>) {
    setBusy(true);
    setError(null);
    try {
      onLogin(await login());
    } catch (failure) {
      setPassword("");
      setError(errorText(failure, "Could not log in. Try again."));
      setBusy(false);
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    void attempt(() => api.login(username, password));
  }

  return (
    <main className="front">
      <div className="scroll-progress" aria-hidden="true" />
      <div className="front-hero">
        <SignalOrb />
        <header className="front-bar">
          <span className="brand">
            <span className="logo-tile">
              <Radar aria-hidden="true" size={18} />
            </span>
            <span className="product">Casewright</span>
          </span>
        </header>

        <div className="front-center">
          <p className="label">
            <Sparkles aria-hidden="true" size={14} />
            Agentic security analyst
          </p>
          <h1 className="front-headline">
            Every alert,{" "}
            <span className="headline-tile" aria-hidden="true">
              <ShieldCheck />
            </span>{" "}
            <em>investigated.</em>
          </h1>
          <form className="card front-card" onSubmit={submit} aria-label="Log in">
            {demoLogin && (
              <>
                <button
                  type="button"
                  className="button button-primary"
                  disabled={busy}
                  onClick={() => void attempt(() => api.demoLogin())}
                >
                  Try the demo
                </button>
                <p className="small muted">Everything here is made up, and approving an action changes nothing real.</p>
                <p className="small muted login-or">Or log in with your own account:</p>
              </>
            )}
            <label>
              Username
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoFocus={!demoLogin}
                required
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </label>
            {error && (
              <p role="alert" className="error-text">
                {error}
              </p>
            )}
            {/* The main action is white: Log in, unless the public site's "Try the demo" is the main one. */}
            <button type="submit" className={demoLogin ? "button" : "button button-primary"} disabled={busy}>
              {busy ? "Logging in..." : "Log in"}
            </button>
          </form>
          <button type="button" className="button scroll-cue" onClick={showHowItWorks}>
            See how it works
            <ArrowDown aria-hidden="true" size={16} />
          </button>
        </div>
      </div>
      <FrontSections />
    </main>
  );
}

/** Scrolls to the first section (smoothly, unless the visitor asked for reduced motion). */
function showHowItWorks() {
  const still = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  document.getElementById("how-it-works")?.scrollIntoView?.({ behavior: still ? "auto" : "smooth", block: "start" });
}
