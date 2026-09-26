/**
 * SentinelKey Frontend Runtime Configuration
 * Automatically detects whether running locally (Flask / localhost)
 * or hosted statically on Vercel / GitHub Pages.
 */
window.SENTINEL_CONFIG = {
  // Configured backend URL (empty string means relative paths /api/... when served from Flask)
  API_BASE_URL: localStorage.getItem("SENTINEL_API_URL") || "",

  // Format full endpoint path
  api: function(endpoint) {
    if (!endpoint.startsWith("/")) endpoint = "/" + endpoint;
    const base = (this.API_BASE_URL || "").replace(/\/+$/, "");
    return base + endpoint;
  },

  // Allows switching backend host in browser console or settings modal
  setApiUrl: function(url) {
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
