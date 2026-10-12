chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log("1. Background received action:", request.action);

  if (request.action === "SCAN_REPO") {
    console.log("2. Fetching from Python backend: http://127.0.0.1:8000/api/scan");

    fetch("http://127.0.0.1:8000/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({ github_url: request.github_url })
    })
      .then(response => {
        console.log("3. Got response from Python! Status:", response.status);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        console.log("4. Python Data parsed successfully!", data);
        sendResponse({ success: true, data: data });
        console.log("5. Sent data back to popup UI!");
      })
      .catch(error => {
        console.error("❌ Fetch Error:", error);
        sendResponse({ success: false, error: error.message });
      });

    // 🔥 THIS LINE PREVENTS THE INFINITE SPINNER 🔥
    console.log("Keeping message channel open...");
    return true;
  }
});