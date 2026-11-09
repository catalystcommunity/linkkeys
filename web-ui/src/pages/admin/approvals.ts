// The queue of claims that wait for an administrator's approval.
import { api } from "../../transport";
import { claimTypeLabel, t } from "../../i18n";
import { button, h, link, textButton, type Child } from "../../dom";
import type { ClaimApproval } from "../../generated/types.gen";
import { serviceMessage as message } from "../../ui-logic";
import { AdminPage, Slot, adminHeader } from "./common";

function approvalValue(approval: ClaimApproval): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(approval.claimValue); }
  catch { return t("app.account.binary_value"); }
}

export class AdminApprovalsPage extends AdminPage {
  private approvals: ClaimApproval[] = [];
  private loaded = false;
  /** The id of the approval that a decision runs for. */
  private deciding = "";
  private readonly content = new Slot();
  private buttons = new Map<string, ZestPushButton[]>();

  protected build(): Child {
    const header = adminHeader(this.context.path, t("app.approvals.title"), t("app.approvals.intro"));
    return [...header.nodes, h("section", { class: "card" }, this.content.anchor, this.messages.element)];
  }

  protected async start(): Promise<void> {
    this.renderList();
    await this.load(() => this.refresh(), () => t("app.approvals.load_failed"));
  }

  protected async refresh(): Promise<void> {
    const approvals = (await api.admin.listPendingClaimApprovals({})).approvals;
    if (!this.isActive()) return;
    this.approvals = approvals;
    this.loaded = true;
    this.renderList();
  }

  private renderList(): void {
    this.buttons = new Map();
    if (!this.approvals.length) { this.content.set(h("p", { class: "muted" }, this.loaded ? t("app.approvals.empty") : t("app.approvals.loading"))); return; }
    const headings = [t("app.party.field.account_id"), t("app.account.col_detail"), t("app.account.col_value"), t("app.approvals.col_requested"), t("app.account.col_action")];
    this.content.set(h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ...headings.map((text) => h("th", null, text)))),
      h("tbody", null, ...this.approvals.map((approval) => this.row(approval))))));
  }

  private row(approval: ClaimApproval): HTMLTableRowElement {
    const approve = button(t("app.approvals.approve"), { onClick: () => void this.decide(approval, true) });
    const reject = textButton(t("app.approvals.reject"), () => void this.decide(approval, false));
    this.buttons.set(approval.id, [approve, reject]);
    this.markDeciding();
    return h("tr", null,
      h("td", null, link(`/app/admin/users/${encodeURIComponent(approval.userId)}`, h("code", null, approval.userId))),
      h("td", null, claimTypeLabel(approval.claimType)),
      h("td", null, approvalValue(approval)),
      h("td", null, new Date(approval.createdAt).toLocaleString()),
      h("td", null, h("div", { class: "button-row" }, approve, reject)));
  }

  /** Only the buttons of the approval that a decision runs for are off. */
  private markDeciding(): void {
    for (const [id, controls] of this.buttons) for (const control of controls) control.disabled = id === this.deciding;
  }

  private async decide(approval: ClaimApproval, approve: boolean): Promise<void> {
    this.deciding = approval.id;
    this.markDeciding();
    this.messages.clear();
    try {
      if (approve) await api.admin.approveClaim({ approvalId: approval.id });
      else await api.admin.rejectClaim({ approvalId: approval.id });
      if (!this.isActive()) return;
      await this.refresh();
      if (this.isActive()) this.messages.status(approve ? t("app.approvals.approved") : t("app.approvals.rejected"));
    } catch (cause) {
      if (this.isActive()) this.messages.fail(message(cause, t("app.approvals.failed")));
    } finally {
      if (this.deciding === approval.id) this.deciding = "";
      if (this.isActive()) this.markDeciding();
    }
  }
}
