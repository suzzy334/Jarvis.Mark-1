/**
 * SentinelKey Frontend Runtime Configuration
 * Automatically detects whether running locally (Flask / localhost)
 * or hosted statically on Vercel / GitHub Pages.
 */
window.SENTINEL_CONFIG = {
  // If hosted on Vercel or GitHub Pages, automatically route to the live Render backend
  API_BASE_URL: localStorage.getItem("SENTINEL_API_URL") || (
    typeof window !== "undefined" && (window.location.hostname.includes("vercel.app") || window.location.hostname.includes("github.io"))
      ? "https://sentinelkey-backend.onrender.com"
      : ""
  ),

  // Format full endpoint path
  api: function (endpoint) {
    if (!endpoint.startsWith("/")) endpoint = "/" + endpoint;
    const base = (this.API_BASE_URL || "").replace(/\/+$/, "");
    return base + endpoint;
  },

  // Allows switching backend host in browser console or settings modal
  setApiUrl: function (url) {
    if (url) {
      localStorage.setItem("SENTINEL_API_URL", url);
      this.API_BASE_URL = url;
      console.log("[SentinelKey] API backend URL set to:", url);
    } else {
      localStorage.removeItem("SENTINEL_API_URL");
      this.API_BASE_URL = "";
      console.log("[SentinelKey] API backend URL reset to local relative path.");
    }
  }
};

// Global transparent fetch proxy: rewrites relative /api/ requests to Render backend when hosted on Vercel
// and automatically injects session authentication headers and credentials
(function () {
  if (typeof window !== "undefined" && window.fetch) {
    const originalFetch = window.fetch;
    window.fetch = function (resource, init) {
      init = init || {};
      
      // Inject session token if present
      const token = localStorage.getItem("sentinel_session_token") || 
                    sessionStorage.getItem("sentinel_session_token") ||
                    (document.cookie.split("; ").find(r => r.startsWith("session_token=")) || "").split("=")[1];
      
      if (token) {
        if (!init.headers) {
          init.headers = {
            "Authorization": "Bearer " + token,
            "X-Session-Token": token
          };
        } else if (init.headers instanceof Headers) {
          if (!init.headers.has("Authorization")) init.headers.set("Authorization", "Bearer " + token);
          if (!init.headers.has("X-Session-Token")) init.headers.set("X-Session-Token", token);
        } else if (Array.isArray(init.headers)) {
          init.headers.push(["Authorization", "Bearer " + token]);
          init.headers.push(["X-Session-Token", token]);
        } else {
          if (!init.headers["Authorization"]) init.headers["Authorization"] = "Bearer " + token;
          if (!init.headers["X-Session-Token"]) init.headers["X-Session-Token"] = token;
        }
      }
      
      if (!init.credentials) {
        init.credentials = "include";
      }

      if (typeof resource === "string" && resource.startsWith("/api/")) {
        const baseUrl = window.SENTINEL_CONFIG && window.SENTINEL_CONFIG.API_BASE_URL;
        if (baseUrl) {
          resource = baseUrl.replace(/\/+$/, "") + resource;
        }
      }
      return originalFetch(resource, init);
    };
  }
})();
