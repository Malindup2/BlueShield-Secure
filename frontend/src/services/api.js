import axios from "axios";
import API_BASE_URL from "../config/api";

const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
});

// Request interceptor to add the auth token to headers
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle unauthenticated sessions globally
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // V13: previously commented out, so an expired or revoked token left
    // the client believing it was still signed in. Access tokens are now
    // short lived, which makes handling this mandatory rather than optional.
    if (error.response && error.response.status === 401) {
      localStorage.removeItem("token");
      localStorage.removeItem("userRole");
      localStorage.removeItem("user");

      // Avoid a redirect loop when the failing request is the sign-in itself.
      if (!window.location.pathname.startsWith("/login")) {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

export default api;
