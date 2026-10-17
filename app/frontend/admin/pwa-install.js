(function () {
  "use strict";

  const scriptOptions = document.currentScript?.dataset || {};
  const MANIFEST_PATH = scriptOptions.manifest || "/pay.webmanifest";
  const ANDROID_APK_PATH =
    scriptOptions.androidApk || "/bolt12-pay-companion.apk";
  const LABEL_KEYS = {
    ready: scriptOptions.labelReady || "nav.install",
    checking: scriptOptions.labelChecking || "nav.install_checking",
    help: scriptOptions.labelHelp || "nav.install_help",
    manual: scriptOptions.labelManual || "nav.install_manual",
  };
  const RELOAD_MARKER = "bolt12pay.pwa-reinstall-reload";
  const promptWaiters = new Set();

  let deferredPrompt = null;
  let registration = null;
  let installedState = null;

  function hasReloadMarker() {
    try {
      return sessionStorage.getItem(RELOAD_MARKER) === "1";
    } catch {
      return false;
    }
  }

  function setReloadMarker() {
    try {
      sessionStorage.setItem(RELOAD_MARKER, "1");
    } catch {}
  }

  function clearReloadMarker() {
    try {
      sessionStorage.removeItem(RELOAD_MARKER);
    } catch {}
  }

  function isStandalone() {
    return (
      window.matchMedia("(display-mode: standalone)").matches ||
      window.matchMedia("(display-mode: fullscreen)").matches ||
      window.navigator.standalone === true
    );
  }

  function isAndroid() {
    return (
      navigator.userAgentData?.platform === "Android" ||
      /Android/i.test(navigator.userAgent || "")
    );
  }

  function isIos() {
    return (
      /iPad|iPhone|iPod/i.test(navigator.userAgent || "") ||
      (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1)
    );
  }

  function setupAndroidCompanionDownload() {
    const button = document.getElementById("androidCompanionBtn");
    if (!button) return;

    button.hidden = !isAndroid();
    if (button.hidden) return;
    button.addEventListener("click", () => {
      window.location.assign(ANDROID_APK_PATH);
    });
  }

  function translated(key, fallback) {
    if (typeof window.__t === "function") {
      const value = window.__t(key);
      if (value && value !== key) return value;
    }
    return fallback;
  }

  function setButtonState(state) {
    const button = document.getElementById("installBtn");
    const label = button?.querySelector("[data-i18n]") || button;
    if (!button || !label) return;

    button.dataset.installState = state;
    button.hidden = state === "installed" || state === "standalone";
    button.disabled = state === "checking";

    const labels = {
      ready: [LABEL_KEYS.ready, "Install app"],
      checking: [LABEL_KEYS.checking, "Checking installation…"],
      help: [LABEL_KEYS.help, "Installation help"],
    };
    const [key, fallback] = labels[state] || labels.help;
    label.dataset.i18n = key;
    label.textContent = translated(key, fallback);
  }

  function resolvePromptWaiters() {
    for (const resolve of promptWaiters) resolve(true);
    promptWaiters.clear();
  }

  function waitForPrompt(timeoutMs) {
    if (deferredPrompt) return Promise.resolve(true);
    return new Promise((resolve) => {
      const timer = window.setTimeout(() => {
        promptWaiters.delete(done);
        resolve(false);
      }, timeoutMs);
      const done = (available) => {
        window.clearTimeout(timer);
        resolve(available);
      };
      promptWaiters.add(done);
    });
  }

  async function isPayAppInstalled() {
    if (isStandalone()) return true;
    if (typeof navigator.getInstalledRelatedApps !== "function") return null;

    try {
      const installedApps = await navigator.getInstalledRelatedApps();
      return installedApps.some((app) => {
        if (app.platform !== "webapp" || !app.url) return false;
        try {
          return new URL(app.url, window.location.href).pathname === MANIFEST_PATH;
        } catch {
          return false;
        }
      });
    } catch (error) {
      console.warn("Unable to query installed PWA state", error);
      return null;
    }
  }

  async function refreshInstallState({ reloadIfRemoved = false } = {}) {
    if (isStandalone()) {
      installedState = true;
      setButtonState("standalone");
      return;
    }

    const currentState = await isPayAppInstalled();
    const wasRemoved = installedState === true && currentState === false;
    installedState = currentState;

    if (wasRemoved && reloadIfRemoved) {
      if (!hasReloadMarker()) {
        setReloadMarker();
        window.location.reload();
        return;
      }
    }

    if (currentState === true) {
      setButtonState("installed");
    } else if (deferredPrompt) {
      clearReloadMarker();
      setButtonState("ready");
    } else {
      setButtonState("help");
    }
  }

  async function registerServiceWorker() {
    if (!("serviceWorker" in navigator)) return null;

    registration = await navigator.serviceWorker.register(
      "/service-worker.js",
      {
        scope: "/",
        updateViaCache: "none",
      },
    );
    await navigator.serviceWorker.ready;
    return registration;
  }

  async function showInstallPrompt() {
    const promptEvent = deferredPrompt;
    if (!promptEvent) return false;

    deferredPrompt = null;
    setButtonState("checking");

    try {
      await promptEvent.prompt();
      const choice = await promptEvent.userChoice;
      if (choice?.outcome === "accepted") {
        setButtonState("installed");
      } else {
        setButtonState("help");
      }
      return choice?.outcome === "accepted";
    } catch (error) {
      console.warn("PWA install prompt failed", error);
      setButtonState("help");
      return false;
    }
  }

  async function handleInstallClick() {
    if (deferredPrompt) {
      await showInstallPrompt();
      return;
    }

    setButtonState("checking");
    try {
      if (!registration) registration = await registerServiceWorker();
      await registration?.update();
    } catch (error) {
      console.warn("Service Worker refresh failed", error);
    }

    if (await waitForPrompt(1500)) {
      await showInstallPrompt();
      return;
    }

    setButtonState("help");
    const message = isIos()
      ? translated(
          "nav.install_manual_ios",
          "Open this page in Safari, tap Share, and choose ‘Add to Home Screen’. Press OK to reload now.",
        )
      : translated(
          LABEL_KEYS.manual,
          "Chrome is not offering the direct install dialog right now. Reload once after uninstalling, or use Chrome’s menu and choose ‘Install app’ or ‘Add to Home screen’. Press OK to reload now.",
        );
    if (window.confirm(message)) window.location.reload();
  }

  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    deferredPrompt = event;
    clearReloadMarker();
    resolvePromptWaiters();
    setButtonState("ready");
  });

  window.addEventListener("appinstalled", () => {
    deferredPrompt = null;
    installedState = true;
    clearReloadMarker();
    setButtonState("installed");
  });

  async function init() {
    const button = document.getElementById("installBtn");
    if (!button) return;

    setupAndroidCompanionDownload();
    button.addEventListener("click", handleInstallClick);
    setButtonState("checking");

    try {
      await registerServiceWorker();
    } catch (error) {
      console.error("Service Worker registration failed", error);
    }

    await refreshInstallState();

    const displayMode = window.matchMedia("(display-mode: standalone)");
    const handleDisplayModeChange = () => refreshInstallState();
    if (typeof displayMode.addEventListener === "function") {
      displayMode.addEventListener("change", handleDisplayModeChange);
    } else {
      displayMode.addListener?.(handleDisplayModeChange);
    }

    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") {
        refreshInstallState({ reloadIfRemoved: true });
      }
    });
    window.addEventListener("pageshow", () => refreshInstallState());
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }

  window.Bolt12PwaInstall = {
    isStandalone,
    isAndroid,
    isIos,
    refresh: refreshInstallState,
  };
})();
