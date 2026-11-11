import { useEffect, useState, type FormEvent } from "react";

import { api } from "../api";
import type { User } from "../types";

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
      setError(failure instanceof Error ? failure.message : "Could not log in. Try again.");
      setBusy(false);
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    void attempt(() => api.login(username, password));
  }

  return (
    <main className="login-page">
      <form className="login-card" onSubmit={submit}>
        <h1>Casewright</h1>
        {demoLogin ? (
          <>
            <p className="muted">
              Try it with a shared demo account. Everything here is made up, and approving an action changes nothing
              real.
            </p>
            <button
              type="button"
              className="button button-primary"
              disabled={busy}
              onClick={() => void attempt(() => api.demoLogin())}
            >
              Try the demo
            </button>
            <p className="muted login-or">Or log in with your own account:</p>
          </>
        ) : (
          <p className="muted">Log in to see incidents and decide what happens next.</p>
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
        <button type="submit" className={demoLogin ? "button" : "button button-primary"} disabled={busy}>
          {busy ? "Logging in..." : "Log in"}
        </button>
      </form>
    </main>
  );
}
