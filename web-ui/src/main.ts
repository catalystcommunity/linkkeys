// Start the LinkKeys UI: load the configuration and the message catalog,
// define the Zest controls, and start the app shell.
import "@catalystcommunity/design-tokens/src/tokens.css";
import "./styles.css";
import { defineControls } from "@catalystcommunity/controls";
import { defineElements } from "@catalystcommunity/base-components";
import { DateTimePicker } from "@catalystcommunity/date-time-picker";
import { api } from "./transport";
import { addStylesheet } from "./host";
import { t, useCatalog } from "./i18n";
import { query } from "./shared";
import { LinkKeysApp } from "./app";

/** Load the home domain's catalog for this browser's languages. The bundled
 * en-US catalog stays in use when this fails, so the UI still starts. */
async function loadCatalog(): Promise<void> {
  try { useCatalog(await api.i18n.getTranslations({ locale: query("lang") || undefined, acceptLanguage: navigator.languages.join(",") })); }
  catch (error) { console.warn("The LinkKeys message catalog could not load. Using en-US.", error); }
}

async function start(): Promise<void> {
  const root = document.getElementById("root")!;
  try {
    defineControls();
    defineElements({ "date-time-picker": DateTimePicker });
    const [configuration] = await Promise.all([api.ui.getConfiguration({}), loadCatalog()]);
    document.title = configuration.display.siteName;
    if (configuration.theme?.stylesheetUrl) addStylesheet(configuration.theme.stylesheetUrl, "operator-theme");
    if (configuration.theme?.faviconUrl) { const favicon = document.createElement("link"); favicon.rel = "icon"; favicon.href = configuration.theme.faviconUrl; document.head.append(favicon); }
    await new LinkKeysApp(configuration, root).start();
  } catch (error) {
    console.error("The LinkKeys UI could not start.", error);
    const main = document.createElement("main"); main.className = "wrap narrow";
    const card = document.createElement("section"); card.className = "card";
    const title = document.createElement("h1"); title.textContent = t("app.start.failed_title");
    const detail = document.createElement("p"); detail.textContent = t("app.start.failed_body");
    card.append(title, detail); main.append(card);
    root.replaceChildren(main);
  }
}

void start();
