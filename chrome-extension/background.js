"use strict";

const MENU_ID = "cvstudio-open-sidepanel";

async function ensurePanelBehavior(){
  try{
    await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
  }catch(_){}
}

function rebuildContextMenu(){
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_ID,
      title: "Open CV Studio Tailor panel",
      contexts: ["page", "selection", "link"]
    });
  });
}

chrome.runtime.onInstalled.addListener(async () => {
  await ensurePanelBehavior();
  rebuildContextMenu();
});

chrome.runtime.onStartup.addListener(async () => {
  await ensurePanelBehavior();
  rebuildContextMenu();
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if(info.menuItemId !== MENU_ID || !tab || !tab.windowId) return;
  try{
    if(typeof tab.id === "number"){
      await chrome.sidePanel.setOptions({
        tabId: tab.id,
        path: "sidepanel.html",
        enabled: true
      });
    }
    await chrome.sidePanel.open({ windowId: tab.windowId });
  }catch(_){}
});
