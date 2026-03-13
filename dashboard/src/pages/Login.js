import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    navigate('/');
  };

  const handleGuest = () => {
    navigate('/');
  };

  return (
    <div className="login-wrapper">
      <div className="login-card">
        <div className="login-logo">
          <div className="login-logo-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <h1>IoT Trust & Drift</h1>
          <p>Security Operations Center</p>
        </div>

        <form className="login-form" onSubmit={handleLogin}>
          <div className="login-field">
            <label>Username</label>
            <input
              type="text"
              placeholder="Enter your username"
              value={username}
              onChange={e => setUsername(e.target.value)}
              autoComplete="username"
            />
          </div>
          <div className="login-field">
            <label>Password</label>
            <input
              type="password"
              placeholder="Enter your password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </div>
          <button type="submit" className="login-btn">Sign In</button>
        </form>

        <div className="login-divider">
          <span>or</span>
        </div>

        <button className="login-guest-btn" onClick={handleGuest}>
          Continue as Guest
        </button>
      </div>
    </div>
  );
}

export default Login;
