const BACKEND_URL = "https://traceroot-br3o.onrender.com";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log("1. Background received action:", request?.action);

  // 1. Health check action for live status indicator
  if (request.action === "CHECK_HEALTH") {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);

    fetch(`${BACKEND_URL}/health`, { signal: controller.signal })
      .then((res) => {
        clearTimeout(timeoutId);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => sendResponse({ success: true, data }))
      .catch((err) => {
        clearTimeout(timeoutId);
        sendResponse({ success: false, error: err.message });
      });

    return true;
  }

  // 2. Repository dependency audit action
  if (request.action === "SCAN_REPO") {
    console.log("2. Fetching from Python backend:", `${BACKEND_URL}/api/scan`);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout

    fetch(`${BACKEND_URL}/api/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({ github_url: request.github_url }),
      signal: controller.signal
    })
      .then(async (response) => {
        clearTimeout(timeoutId);
        console.log("3. Got response from Python! Status:", response.status);

        if (!response.ok) {
          let errorMsg = `HTTP error! status: ${response.status}`;
          try {
            const errorJson = await response.json();
            if (errorJson && errorJson.detail) {
              errorMsg = typeof errorJson.detail === "string"
                ? errorJson.detail
                : JSON.stringify(errorJson.detail);
            }
          } catch (_) {
            // Body was not JSON
          }
          throw new Error(errorMsg);
        }
        return response.json();
      })
      .then((data) => {
        console.log("4. Python Data parsed successfully!", data);
        sendResponse({ success: true, data: data });
        console.log("5. Sent data back to popup UI!");
      })
      .catch((error) => {
        clearTimeout(timeoutId);
        console.error("❌ Fetch Error:", error);
        const errorMsg = error.name === "AbortError"
          ? "Scan timed out (30s limit exceeded). The repository may be too large or the scanner is busy."
          : error.message;
        sendResponse({ success: false, error: errorMsg });
      });

    // Keep message channel open for async response
    console.log("Keeping message channel open...");
    return true;
  }
});