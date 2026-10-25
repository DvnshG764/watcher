document.addEventListener("DOMContentLoaded", () => {
  const syncBtn = document.getElementById("sync-now-btn");
  const syncStatus = document.getElementById("sync-status-text");

  // --- CONFIGURATION ---
  const GITHUB_REPO = "DvnshG764/watcher";
  const WORKFLOW_FILE = "update_data.yml";
  const BRANCH = "v2";
  const ADMIN_USERNAME = "admin"; // Change this to your preferred username
  
  // PASTE YOUR ENCRYPTED STRING HERE (Keep the quotes)
  const ENCRYPTED_GITHUB_TOKEN = "U2FsdGVkX1...PASTE_YOURS_HERE"; 

  if (syncBtn && syncStatus) {
    syncBtn.addEventListener("click", async () => {
      // 1. Prompt for Custom Username and Password
      const usernameInput = prompt("Enter Admin Username:");
      if (usernameInput !== ADMIN_USERNAME) {
        alert("Unauthorized: Incorrect username.");
        return;
      }

      const passwordInput = prompt("Enter Admin Password:");
      if (!passwordInput) return;

      // 2. Unscramble the GitHub Token
      let decryptedToken = "";
      try {
        const bytes = CryptoJS.AES.decrypt(ENCRYPTED_GITHUB_TOKEN, passwordInput);
        decryptedToken = bytes.toString(CryptoJS.enc.Utf8);
      } catch (e) {}

      if (!decryptedToken.startsWith("ghp_")) {
        alert("Unauthorized: Incorrect password.");
        return;
      }

      // 3. Save original button HTML (to keep the SVG icon safe) and Update UI
      const originalBtnHTML = syncBtn.innerHTML;
      syncBtn.innerText = "Loading..";
      syncBtn.disabled = true;
      syncStatus.innerText = "Syncing Now";

      try {
        // 4. Trigger GitHub Action
        const triggerRes = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/actions/workflows/${WORKFLOW_FILE}/dispatches`, {
          method: "POST",
          headers: {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": `Bearer ${decryptedToken}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            ref: BRANCH,
            inputs: { branch_name: BRANCH, environment: "production" }
          })
        });

        if (!triggerRes.ok) throw new Error("Failed to trigger workflow.");

        // 5. Wait 10 seconds for GitHub to queue the job
        await new Promise(resolve => setTimeout(resolve, 10000));

        // 6. Poll GitHub for completion
        let isComplete = false;
        while (!isComplete) {
          const statusRes = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/actions/workflows/${WORKFLOW_FILE}/runs?branch=${BRANCH}&event=workflow_dispatch&per_page=1`, {
            headers: {
              "Accept": "application/vnd.github.v3+json",
              "Authorization": `Bearer ${decryptedToken}`
            }
          });
          
          const data = await statusRes.json();
          
          if (data.workflow_runs && data.workflow_runs.length > 0) {
            const latestRun = data.workflow_runs[0];

            if (latestRun.status === "completed") {
              isComplete = true;
              if (latestRun.conclusion !== "success") {
                alert(`Sync finished with errors: ${latestRun.conclusion}`);
              }
            } else {
              await new Promise(resolve => setTimeout(resolve, 15000));
            }
          } else {
            await new Promise(resolve => setTimeout(resolve, 10000));
          }
        }

      } catch (error) {
        console.error("Error during sync:", error);
        alert("An error occurred during sync. Check the browser console.");
      } finally {
        // 7. Restore UI (Putting the text and SVG icon back!)
        syncBtn.innerHTML = originalBtnHTML;
        syncBtn.disabled = false;
        syncStatus.innerText = "All Feeds Synced";
      }
    });
  }
});
