// The base class of each LinkKeys page. A page is a Zest light-DOM component:
// it builds its elements one time when it first connects, then changes only
// the parts that change. The app shell makes a new page for each route.
import { BaseComponent, defineElements } from "@catalystcommunity/base-components";
import { nodes, type Child } from "./dom";
import type { PageProps } from "./shared";

export abstract class Page extends BaseComponent {
  /** Set by the shell before the page connects. */
  context!: PageProps;
  private built = false;

  connectedCallback(): void {
    super.connectedCallback();
    if (this.built) return;
    this.built = true;
    this.replaceChildren(...nodes(this.build()));
    void this.start();
  }

  /** The page's elements. Runs one time. */
  protected abstract build(): Child;

  /** Work after the first build, for example the first load. After each
   * `await`, check `this.isActive()` before you change the page. */
  protected async start(): Promise<void> {}
}

/** Define a page class under `tag` (once) and make an instance of it. */
export function createPage<T extends Page>(tag: string, pageClass: new () => T, context: PageProps): T {
  defineElements({ [tag]: pageClass });
  const page = document.createElement(tag) as T;
  page.classList.add("lk-page");
  page.context = context;
  return page;
}
