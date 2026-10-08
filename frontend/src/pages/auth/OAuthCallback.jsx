import React, { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import toast from "react-hot-toast";
import { useAuth } from "../../context/AuthContext";

const ROLE_DASHBOARDS = {
  FISHERMAN: "/dashboard/fisherman",
  OFFICER: "/dashboard/officer",
  HAZARD_ADMIN: "/dashboard/hazard-admin",
  ILLEGAL_ADMIN: "/dashboard/illegal-admin",
  SYSTEM_ADMIN: "/dashboard/system-admin",
};

const ERROR_MESSAGES = {
  access_denied: "You cancelled the Google sign-in.",
  invalid_session: "That sign-in attempt has expired. Please try again.",
  state_mismatch: "The sign-in request could not be verified. Please try again.",
  nonce_mismatch: "The sign-in response could not be verified. Please try again.",
  missing_code: "Google did not return an authorisation code.",
  token_exchange_failed: "Could not complete sign-in with Google.",
  invalid_issuer: "The sign-in response came from an unexpected issuer.",
  email_not_verified: "Your Google account email is not verified.",
  account_disabled: "This account has been disabled.",
  authentication_failed: "Google sign-in failed. Please try again.",
};

const OAuthCallback = () => {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const { completeOAuthLogin } = useAuth();
  const [error, setError] = useState(null);

  // React 18 StrictMode mounts effects twice in development; the handle is
  // single-use, so a second exchange would always fail.
  const exchanged = useRef(false);

  useEffect(() => {
    if (exchanged.current) return;
    exchanged.current = true;

    const failure = params.get("error");
    if (failure) {
      setError(ERROR_MESSAGES[failure] || "Google sign-in failed.");
      return;
    }

    const handle = params.get("handle");
    if (!handle) {
      setError("This sign-in link is incomplete.");
      return;
    }

    completeOAuthLogin(handle)
      .then((data) => {
        toast.success(`Welcome, ${data.name}`);
        navigate(ROLE_DASHBOARDS[data.role] || "/", { replace: true });
      })
      .catch(() => {
        setError("This sign-in link has expired or already been used.");
      });
  }, [params, completeOAuthLogin, navigate]);

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4">
        <div className="w-full max-w-sm rounded-lg bg-white p-8 text-center shadow">
          <h1 className="text-lg font-semibold text-slate-900">Sign-in failed</h1>
          <p className="mt-2 text-sm text-slate-600">{error}</p>
          <Link
            to="/login"
            className="mt-6 inline-block rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white"
          >
            Back to sign in
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4">
      <div className="text-center">
        <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-slate-300 border-t-slate-900" />
        <p className="mt-4 text-sm text-slate-600">Completing sign-in…</p>
      </div>
    </div>
  );
};

export default OAuthCallback;
